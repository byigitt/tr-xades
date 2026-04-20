// CAdES seviye yükseltici. BES/EPES → T → LT → LTA.
//
// Tek `cadesUpgrade()`; opts.to discriminated union.
//   to:"T"   — signature-time-stamp (§6.1.1): SignerInfo.signature üzerinde RFC 3161.
//   to:"LT"  — certificate-values + revocation-values (§6.2): chain + CRL/OCSP.
//   to:"LTA" — archive-time-stamp-v2 (§6.4.1): SignedData bölümleri üzerinde
//             concat ile hash, yeni TS unsignedAttrs'a eklenir.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
	buildCertValuesAttr,
	buildRevocationValuesAttr,
	buildSignatureTimeStampAttr,
} from "./cades-attributes.ts";
import { CADES_ATTR, CONTENT_TYPE } from "./cades-constants.ts";
import { digest, type HashAlg } from "./crypto.ts";
import { getTimestamp } from "./tsp.ts";

export type CadesUpgradeOptions =
	| { bytes: Uint8Array; to: "T"; tsa?: { url?: string; policyOid?: string }; digestAlgorithm?: HashAlg }
	| { bytes: Uint8Array; to: "LT"; chain: Uint8Array[]; crls?: Uint8Array[]; ocsps?: Uint8Array[] }
	| { bytes: Uint8Array; to: "LTA"; tsa?: { url?: string; policyOid?: string }; digestAlgorithm?: HashAlg; detachedContent?: Uint8Array };

export async function cadesUpgrade(opts: CadesUpgradeOptions): Promise<Uint8Array> {
	const asn = asn1js.fromBER(toAB(opts.bytes));
	if (asn.offset === -1) throw new Error("cadesUpgrade: ASN.1 parse hatası");
	const ci = new pkijs.ContentInfo({ schema: asn.result });
	if (ci.contentType !== CONTENT_TYPE.signedData) {
		throw new Error(`cadesUpgrade: ContentType SignedData değil: ${ci.contentType}`);
	}
	const sd = new pkijs.SignedData({ schema: ci.content });
	if (sd.signerInfos.length !== 1) {
		throw new Error(`cadesUpgrade: tek signerInfo bekleniyor, ${sd.signerInfos.length} var`);
	}
	const si = sd.signerInfos[0]!;

	if (opts.to === "T") await addSignatureTimeStamp(si, opts);
	else if (opts.to === "LT") addLongTermValues(si, opts);
	else if (opts.to === "LTA") await addArchiveTimeStamp(sd, si, opts);

	// Re-serialize SignedData → ContentInfo
	const out = new pkijs.ContentInfo({
		contentType: CONTENT_TYPE.signedData,
		content: sd.toSchema(true),
	});
	return new Uint8Array(out.toSchema().toBER());
}

async function addSignatureTimeStamp(
	si: pkijs.SignerInfo,
	opts: Extract<CadesUpgradeOptions, { to: "T" }>,
): Promise<void> {
	const hashAlg = opts.digestAlgorithm ?? "SHA-256";
	const sigBytes = new Uint8Array(si.signature.valueBlock.valueHexView);
	const d = await digest(hashAlg, sigBytes);
	const ts = await getTimestamp({
		digest: d,
		digestAlgorithm: hashAlg,
		tsaUrl: opts.tsa?.url,
		policyOid: opts.tsa?.policyOid,
	});

	addUnsignedAttr(si, buildSignatureTimeStampAttr(ts.token));
}

function addLongTermValues(
	si: pkijs.SignerInfo,
	opts: Extract<CadesUpgradeOptions, { to: "LT" }>,
): void {
	addUnsignedAttr(si, buildCertValuesAttr(opts.chain));
	const crls = opts.crls ?? [];
	const ocsps = opts.ocsps ?? [];
	if (crls.length === 0 && ocsps.length === 0) return;
	addUnsignedAttr(si, buildRevocationValuesAttr({ crls, ocsps }));
}

function addUnsignedAttr(si: pkijs.SignerInfo, a: pkijs.Attribute): void {
	if (!si.unsignedAttrs) {
		si.unsignedAttrs = new pkijs.SignedAndUnsignedAttributes({ type: 1, attributes: [a] });
	} else {
		si.unsignedAttrs.attributes = [...si.unsignedAttrs.attributes, a];
	}
}

// Prior archiveTimeStamp'ları filtrelemek için OID seti.
const ATS_OIDS = new Set<string>([
	CADES_ATTR.archiveTimeStamp,
	CADES_ATTR.archiveTimeStampV2,
	CADES_ATTR.archiveTimeStampV3,
]);

// ETSI TS 101 733 §6.4.1 archive-time-stamp-v2 message imprint input:
// DER(eContent) || DER(certs)* || DER(crls)* || DER(si.version) || DER(si.sid) ||
// DER(si.digestAlgorithm) || DER(si.signedAttrs [0] IMPLICIT) ||
// DER(si.signatureAlgorithm) || DER(si.signature) ||
// her unsignedAttr DER (prior ATS hariç).
async function addArchiveTimeStamp(
	sd: pkijs.SignedData,
	si: pkijs.SignerInfo,
	opts: Extract<CadesUpgradeOptions, { to: "LTA" }>,
): Promise<void> {
	const hashAlg = opts.digestAlgorithm ?? "SHA-256";
	const parts: ArrayBuffer[] = [];

	// eContent (attached ise mevcut, detached ise dişarıdan verilen data iç içe yazılır)
	const ec = sd.encapContentInfo.eContent;
	if (ec) parts.push(ec.toBER(false));
	else if (opts.detachedContent) {
		parts.push(new asn1js.OctetString({ valueHex: toAB(opts.detachedContent) }).toBER(false));
	}

	for (const c of sd.certificates ?? []) parts.push(c.toSchema().toBER(false));
	for (const r of sd.crls ?? []) parts.push(r.toSchema().toBER(false));

	parts.push(new asn1js.Integer({ value: si.version }).toBER(false));
	parts.push((si.sid as asn1js.BaseBlock).toBER(false));
	parts.push(si.digestAlgorithm.toSchema().toBER(false));
	if (si.signedAttrs) parts.push(si.signedAttrs.toSchema().toBER(false));
	parts.push(si.signatureAlgorithm.toSchema().toBER(false));
	parts.push(si.signature.toBER(false));

	if (si.unsignedAttrs) {
		for (const a of si.unsignedAttrs.attributes) {
			if (ATS_OIDS.has(a.type)) continue;
			parts.push(a.toSchema().toBER(false));
		}
	}

	const total = concat(parts);
	const d = await digest(hashAlg, total);
	const ts = await getTimestamp({
		digest: d,
		digestAlgorithm: hashAlg,
		tsaUrl: opts.tsa?.url,
		policyOid: opts.tsa?.policyOid,
	});

	// ArchiveTimeStampV2 attribute value = TimeStampToken (ContentInfo).
	const atsSchema = asn1js.fromBER(toAB(ts.token)).result;
	addUnsignedAttr(si, new pkijs.Attribute({
		type: CADES_ATTR.archiveTimeStampV2,
		values: [atsSchema],
	}));
}

function concat(buffers: ArrayBuffer[]): Uint8Array {
	const total = buffers.reduce((s, b) => s + b.byteLength, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const b of buffers) { out.set(new Uint8Array(b), off); off += b.byteLength; }
	return out;
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
