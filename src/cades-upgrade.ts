// CAdES seviye yükseltici. BES/EPES → T → LT → LTA (LTA v0.4.x).
//
// Tek `cadesUpgrade()`; opts.to discriminated union.
//   to:"T"  — signature-time-stamp (§6.1.1): SignerInfo.signature üzerinde RFC 3161.
//   to:"LT" — certificate-values + revocation-values (§6.2): chain + CRL/OCSP.
// Kullanıcı hedef seviyeye göre sırayla çağırır (BES→T→LT).

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
	buildCertValuesAttr,
	buildRevocationValuesAttr,
	buildSignatureTimeStampAttr,
} from "./cades-attributes.ts";
import { CONTENT_TYPE } from "./cades-constants.ts";
import { digest, type HashAlg } from "./crypto.ts";
import { getTimestamp } from "./tsp.ts";

export type CadesUpgradeOptions =
	| { bytes: Uint8Array; to: "T"; tsa?: { url?: string; policyOid?: string }; digestAlgorithm?: HashAlg }
	| { bytes: Uint8Array; to: "LT"; chain: Uint8Array[]; crls?: Uint8Array[]; ocsps?: Uint8Array[] };

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

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
