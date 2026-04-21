// CAdES imzalı / imzasız attribute builder'ları.
// RFC 5652 + RFC 5035 (ESSCertIDv2) + ETSI TS 101 733 §5 yapıları; her biri
// pkijs.Attribute döner (SignerInfo.signedAttrs / unsignedAttrs listesine konur).

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { CADES_ATTR, CMS_COMMITMENT_OID, CONTENT_TYPE, HASH_OID, SIGNED_ATTR } from "./cades-constants.ts";
import { digest, type HashAlg } from "./crypto.ts";
import type { Policy } from "./policy.ts";
import type { CommitmentType } from "./signed-properties.ts";

function attr(type: string, value: asn1js.BaseBlock): pkijs.Attribute {
	return new pkijs.Attribute({ type, values: [value] });
}

// --- Signed attributes ---

export function buildContentTypeAttr(contentOid: string = CONTENT_TYPE.data): pkijs.Attribute {
	return attr(SIGNED_ATTR.contentType, new asn1js.ObjectIdentifier({ value: contentOid }));
}

export function buildMessageDigestAttr(digestBytes: Uint8Array): pkijs.Attribute {
	return attr(SIGNED_ATTR.messageDigest, new asn1js.OctetString({ valueHex: toAB(digestBytes) }));
}

export function buildSigningTimeAttr(date: Date): pkijs.Attribute {
	// CMS §11.3: UTCTime for 1950–2049, GeneralizedTime otherwise.
	const year = date.getUTCFullYear();
	const block = year >= 1950 && year <= 2049
		? new asn1js.UTCTime({ valueDate: date })
		: new asn1js.GeneralizedTime({ valueDate: date });
	return attr(SIGNED_ATTR.signingTime, block);
}

// RFC 5035 SigningCertificateV2:
//   SigningCertificateV2 ::= SEQUENCE { certs SEQ OF ESSCertIDv2, policies SEQ OF PolicyInfo OPTIONAL }
//   ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgId DEFAULT sha256, certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }
//   IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertSerial }
export async function buildSigningCertificateV2Attr(
	certDer: Uint8Array,
	hashAlg: HashAlg = "SHA-256",
): Promise<pkijs.Attribute> {
	const hash = await digest(hashAlg, certDer);
	const cert = new pkijs.Certificate({ schema: asn1js.fromBER(toAB(certDer)).result });

	const essParts: asn1js.BaseBlock[] = [];
	if (hashAlg !== "SHA-256") {
		// DEFAULT sha256 atlamalı; diğer hash için AlgorithmIdentifier yaz.
		const alg = new pkijs.AlgorithmIdentifier({ algorithmId: HASH_OID[hashAlg] });
		essParts.push(alg.toSchema());
	}
	essParts.push(new asn1js.OctetString({ valueHex: toAB(hash) }));

	// IssuerSerial: GeneralNames(directoryName) + serialNumber
	const issuerGN = new pkijs.GeneralName({ type: 4, value: cert.issuer });
	const generalNames = new asn1js.Sequence({ value: [issuerGN.toSchema()] });
	const issuerSerial = new asn1js.Sequence({ value: [generalNames, cert.serialNumber] });
	essParts.push(issuerSerial);

	const essCertIDv2 = new asn1js.Sequence({ value: essParts });
	const certs = new asn1js.Sequence({ value: [essCertIDv2] });
	const sigCertV2 = new asn1js.Sequence({ value: [certs] });

	return attr(CADES_ATTR.signingCertificateV2, sigCertV2);
}

// ETSI TS 101 733 §5.8.1 SignaturePolicyIdentifier:
//   SEQUENCE { sigPolicyId OID, sigPolicyHash OtherHashAlgAndValue, qualifiers OPT }
export function buildSignaturePolicyIdentifierAttr(policy: Policy): pkijs.Attribute {
	const alg = new pkijs.AlgorithmIdentifier({ algorithmId: HASH_OID[policy.digestAlgorithm] });
	const hashPart = new asn1js.Sequence({
		value: [alg.toSchema(), new asn1js.OctetString({ valueHex: toAB(policy.digest) })],
	});
	const sigPolicyId = new asn1js.Sequence({
		value: [new asn1js.ObjectIdentifier({ value: policy.oid }), hashPart],
	});
	return attr(CADES_ATTR.signaturePolicyIdentifier, sigPolicyId);
}

// ETSI TS 101 733 §5.11.1 CommitmentTypeIndication:
//   SEQUENCE { commitmentTypeId OID, commitmentTypeQualifier OPT }
export function buildCommitmentTypeIndicationAttr(type: CommitmentType): pkijs.Attribute {
	const cti = new asn1js.Sequence({
		value: [new asn1js.ObjectIdentifier({ value: CMS_COMMITMENT_OID[type] })],
	});
	return attr(CADES_ATTR.commitmentTypeIndication, cti);
}

// ETSI TS 101 733 §5.10.1 / RFC 5126 signer-location:
//   SignerLocation ::= SEQUENCE {
//     countryName   [0] DirectoryString OPTIONAL,
//     localityName  [1] DirectoryString OPTIONAL,
//     postalAddress [2] PostalAddress  OPTIONAL }
//   PostalAddress ::= SEQUENCE SIZE (1..6) OF DirectoryString
export function buildSignerLocationAttr(input: {
	city?: string;
	country?: string;
	postal?: string[] | string;
}): pkijs.Attribute {
	const fields: asn1js.BaseBlock[] = [];
	if (input.country !== undefined) {
		fields.push(taggedExplicit(0, new asn1js.Utf8String({ value: input.country })));
	}
	if (input.city !== undefined) {
		fields.push(taggedExplicit(1, new asn1js.Utf8String({ value: input.city })));
	}
	if (input.postal !== undefined) {
		const lines = Array.isArray(input.postal) ? input.postal : [input.postal];
		const pa = new asn1js.Sequence({
			value: lines.map((l) => new asn1js.Utf8String({ value: l })),
		});
		fields.push(taggedExplicit(2, pa));
	}
	return attr(CADES_ATTR.signerLocation, new asn1js.Sequence({ value: fields }));
}

// ETSI TS 101 733 §5.10.3 / RFC 5126 signer-attributes v1:
//   SignerAttribute ::= SEQUENCE OF CHOICE {
//     claimedAttributes   [0] ClaimedAttributes,
//     certifiedAttributes [1] CertifiedAttributes }
//   ClaimedAttributes ::= SEQUENCE OF Attribute
// Biz yalnız claimed (string[]) destekliyoruz; rol için X.520 "title"
// (2.5.4.12) OID kullanılır (XAdES ClaimedRoles ile semantik paralel).
export function buildSignerAttrAttr(claimed: string[]): pkijs.Attribute {
	const title = "2.5.4.12"; // id-at-title
	const attrs = claimed.map((role) => new pkijs.Attribute({
		type: title,
		values: [new asn1js.Utf8String({ value: role })],
	}));
	const claimedSeq = new asn1js.Sequence({ value: attrs.map((a) => a.toSchema()) });
	const choice = taggedExplicit(0, claimedSeq);
	return attr(CADES_ATTR.signerAttr, new asn1js.Sequence({ value: [choice] }));
}

// --- Unsigned attributes ---

// ETSI TS 101 733 §6.1.1 signature-time-stamp: token = CMS ContentInfo (TSTInfo içinde)
export function buildSignatureTimeStampAttr(tstTokenDer: Uint8Array): pkijs.Attribute {
	// Attribute value'su doğrudan TimeStampToken'ın ContentInfo ASN.1 yapısı
	const schema = asn1js.fromBER(toAB(tstTokenDer)).result;
	return attr(CADES_ATTR.signatureTimeStamp, schema);
}

// ETSI TS 101 733 §6.2.1 certificate-values (CAdES-XL):
//   CertificateValues ::= SEQUENCE OF Certificate
// Her DER zaten bir Sequence; doğrudan iç içe konur.
export function buildCertValuesAttr(certs: Uint8Array[]): pkijs.Attribute {
	const nodes = certs.map((d) => asn1js.fromBER(toAB(d)).result);
	return attr(CADES_ATTR.certValues, new asn1js.Sequence({ value: nodes }));
}

// ETSI TS 101 733 §6.2.2 revocation-values (CAdES-XL):
//   RevocationValues ::= SEQUENCE {
//     crlVals      [0] EXPLICIT SEQUENCE OF CertificateList       OPTIONAL,
//     ocspVals     [1] EXPLICIT SEQUENCE OF BasicOCSPResponse     OPTIONAL,
//     otherRevVals [2] EXPLICIT OtherRevVals                      OPTIONAL }
// ocsps parametresi tam OCSPResponse DER alır; spec BasicOCSPResponse istediği
// için iç OCTET STRING açılır ve içeriği (BasicOCSPResponse DER) kullanılır.
export function buildRevocationValuesAttr(input: {
	crls?: Uint8Array[];
	ocsps?: Uint8Array[];
}): pkijs.Attribute {
	const parts: asn1js.BaseBlock[] = [];
	if (input.crls && input.crls.length > 0) {
		const crlNodes = input.crls.map((d) => asn1js.fromBER(toAB(d)).result);
		parts.push(taggedExplicit(0, new asn1js.Sequence({ value: crlNodes })));
	}
	if (input.ocsps && input.ocsps.length > 0) {
		const basicNodes = input.ocsps.map((d) => {
			const resp = new pkijs.OCSPResponse({ schema: asn1js.fromBER(toAB(d)).result });
			if (!resp.responseBytes) throw new Error("buildRevocationValuesAttr: OCSPResponse basic içermiyor");
			const basicDer = new Uint8Array(resp.responseBytes.response.valueBlock.valueHexView);
			return asn1js.fromBER(toAB(basicDer)).result;
		});
		parts.push(taggedExplicit(1, new asn1js.Sequence({ value: basicNodes })));
	}
	return attr(CADES_ATTR.revocationValues, new asn1js.Sequence({ value: parts }));
}

// [n] EXPLICIT inner — RFC tag class=2 (context-specific), constructed.
function taggedExplicit(tag: number, inner: asn1js.BaseBlock): asn1js.BaseBlock {
	return new asn1js.Constructed({
		idBlock: { tagClass: 3, tagNumber: tag },
		value: [inner],
	});
}

// --- helpers ---

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
