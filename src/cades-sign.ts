// CAdES-BES imzalama (ETSI TS 101 733 / EN 319 122 temel profil).
//
// Tek `cadesSign()` fonksiyonu, DER-encoded CMS SignedData (ContentInfo sarıcılı)
// Uint8Array döner. İmzalı/imzasız attribute'lar cades-attributes.ts'ten gelir;
// SignerInfo/SignedData assembly pkijs tarafından yapılır.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
	buildCommitmentTypeIndicationAttr,
	buildContentTypeAttr,
	buildMessageDigestAttr,
	buildSignaturePolicyIdentifierAttr,
	buildSigningCertificateV2Attr,
	buildSigningTimeAttr,
} from "./cades-attributes.ts";
import { CONTENT_TYPE, HASH_OID, SIG_ALG_OID } from "./cades-constants.ts";
import { digest, type HashAlg, type SignatureAlg } from "./crypto.ts";
import { trPolicy, type Policy, type Profile } from "./policy.ts";
import { resolveSigner, type SignerInput } from "./sign.ts";
import type { CommitmentType } from "./signed-properties.ts";

export type CadesSignOptions = {
	data: Uint8Array;
	signer: SignerInput;
	contentIncluded?: boolean; // default true (attached); false → detached
	digestAlgorithm?: HashAlg;
	signatureAlgorithm?: SignatureAlg;
	signingTime?: Date | null; // null → omit; default new Date()
	policy?: Profile | Policy;
	commitmentType?: CommitmentType;
};

export async function cadesSign(opts: CadesSignOptions): Promise<Uint8Array> {
	const resolved = await resolveSigner(opts);
	const digestAlg = opts.digestAlgorithm ?? "SHA-256";
	const contentIncluded = opts.contentIncluded ?? true;

	const cert = new pkijs.Certificate({ schema: asn1js.fromBER(toAB(resolved.certificate)).result });
	const msgDigest = await digest(digestAlg, opts.data);

	const signedAttrs: pkijs.Attribute[] = [
		buildContentTypeAttr(CONTENT_TYPE.data),
		buildMessageDigestAttr(msgDigest),
		await buildSigningCertificateV2Attr(resolved.certificate, digestAlg),
	];
	if (opts.signingTime !== null) {
		signedAttrs.push(buildSigningTimeAttr(opts.signingTime ?? new Date()));
	}
	if (opts.policy) {
		const p = typeof opts.policy === "string" ? trPolicy(opts.policy) : opts.policy;
		signedAttrs.push(buildSignaturePolicyIdentifierAttr(p));
	}
	if (opts.commitmentType) {
		signedAttrs.push(buildCommitmentTypeIndicationAttr(opts.commitmentType));
	}

	const signerInfo = new pkijs.SignerInfo({
		version: 1,
		sid: new pkijs.IssuerAndSerialNumber({
			issuer: cert.issuer,
			serialNumber: cert.serialNumber,
		}),
		digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: HASH_OID[digestAlg] }),
		signedAttrs: new pkijs.SignedAndUnsignedAttributes({ type: 0, attributes: signedAttrs }),
	});

	const signedData = new pkijs.SignedData({
		version: 1,
		encapContentInfo: new pkijs.EncapsulatedContentInfo({
			eContentType: CONTENT_TYPE.data,
			...(contentIncluded
				? { eContent: new asn1js.OctetString({ valueHex: toAB(opts.data) }) }
				: {}),
		}),
		digestAlgorithms: [new pkijs.AlgorithmIdentifier({ algorithmId: HASH_OID[digestAlg] })],
		certificates: [cert],
		signerInfos: [signerInfo],
	});

	// İki imzalama yolu: WebCrypto (pfx/pkcs8) pkijs.SignedData.sign kullanır;
	// PKCS#11 için manuel — signedAttrs SET DER'i elle üretip resolved.sign() ile
	// imzalayıp SignerInfo.signature + signatureAlgorithm'ı elle doldururuz.
	if (resolved.privateKey) {
		await signedData.sign(resolved.privateKey, 0, digestAlg);
	} else {
		// SET OF Attribute (RFC 5652 §5.4) — imzalanırken IMPLICIT [0] yerine açık SET.
		const attrsSet = new asn1js.Set({
			value: signedAttrs.map((a) => a.toSchema()),
		});
		const sigBytes = await resolved.sign(new Uint8Array(attrsSet.toBER()));
		signerInfo.signature = new asn1js.OctetString({ valueHex: toAB(sigBytes) });
		signerInfo.signatureAlgorithm = new pkijs.AlgorithmIdentifier({
			algorithmId: SIG_ALG_OID[resolved.sigAlg],
		});
	}

	const contentInfo = new pkijs.ContentInfo({
		contentType: CONTENT_TYPE.signedData,
		content: signedData.toSchema(true),
	});
	return new Uint8Array(contentInfo.toSchema().toBER());
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
