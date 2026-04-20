// Build the XAdES <xades:SignedProperties> element into a target Document.
// Returns { element, id } — the caller places it and uses the id to reference
// it from SignedInfo.
//
// Shape follows ETSI TS 101 903 v1.4.2 §7.1 (XAdES) and §7.2 (XAdES-EPES).
// Element/attribute ordering is schema-driven (xsd sequence). Verified against
// reference/out/enveloped-bes.xml produced by MA3.

import * as asn1js from "asn1js";
import { Certificate } from "pkijs";
import { C14N, DIGEST, NS } from "./constants.ts";
import { canonicalize } from "./c14n.ts";
import { digest, type HashAlg } from "./crypto.ts";
import { makeId } from "./ids.ts";

export type CommitmentType =
	| "proof-of-origin"
	| "proof-of-receipt"
	| "proof-of-delivery"
	| "proof-of-sender"
	| "proof-of-approval"
	| "proof-of-creation";

const COMMITMENT_OID: Record<CommitmentType, string> = {
	"proof-of-origin": "1.2.840.113549.1.9.16.6.1",
	"proof-of-receipt": "1.2.840.113549.1.9.16.6.2",
	"proof-of-delivery": "1.2.840.113549.1.9.16.6.3",
	"proof-of-sender": "1.2.840.113549.1.9.16.6.4",
	"proof-of-approval": "1.2.840.113549.1.9.16.6.5",
	"proof-of-creation": "1.2.840.113549.1.9.16.6.6",
};

export type SignedPropertiesOptions = {
	certificate: Uint8Array; // end-entity DER
	signingTime?: Date;
	digestAlgorithm?: HashAlg; // for CertDigest — default SHA-256
	productionPlace?: { city?: string; state?: string; postalCode?: string; country?: string };
	signerRole?: { claimed: string[] };
	commitmentType?: CommitmentType;
	dataObjectFormat?: { referenceId: string; mimeType: string };
	policy?: { oid: string; digest: Uint8Array; digestAlgorithm: HashAlg; uri?: string }; // EPES
	id?: string;
};

export async function buildSignedProperties(
	doc: Document,
	opts: SignedPropertiesOptions,
): Promise<{ element: Element; id: string; c14nDigest(alg: HashAlg, c14n: keyof typeof C14N): Promise<Uint8Array> }> {
	const id = opts.id ?? makeId("Signed-Properties");
	const digAlg = opts.digestAlgorithm ?? "SHA-256";

	const sp = el(doc, NS.xades, "xades:SignedProperties");
	sp.setAttribute("Id", id);

	const ssp = el(doc, NS.xades, "xades:SignedSignatureProperties");
	sp.appendChild(ssp);

	if (opts.signingTime) {
		ssp.appendChild(text(doc, NS.xades, "xades:SigningTime", opts.signingTime.toISOString()));
	}

	ssp.appendChild(await buildSigningCertificate(doc, opts.certificate, digAlg));

	if (opts.policy) {
		ssp.appendChild(buildSignaturePolicyIdentifier(doc, opts.policy));
	}

	if (opts.productionPlace) {
		const p = opts.productionPlace;
		const pp = el(doc, NS.xades, "xades:SignatureProductionPlace");
		if (p.city) pp.appendChild(text(doc, NS.xades, "xades:City", p.city));
		if (p.state) pp.appendChild(text(doc, NS.xades, "xades:StateOrProvince", p.state));
		if (p.postalCode) pp.appendChild(text(doc, NS.xades, "xades:PostalCode", p.postalCode));
		if (p.country) pp.appendChild(text(doc, NS.xades, "xades:CountryName", p.country));
		ssp.appendChild(pp);
	}

	if (opts.signerRole) {
		const sr = el(doc, NS.xades, "xades:SignerRole");
		const cr = el(doc, NS.xades, "xades:ClaimedRoles");
		for (const r of opts.signerRole.claimed) {
			cr.appendChild(text(doc, NS.xades, "xades:ClaimedRole", r));
		}
		sr.appendChild(cr);
		ssp.appendChild(sr);
	}

	if (opts.dataObjectFormat || opts.commitmentType) {
		const sdop = el(doc, NS.xades, "xades:SignedDataObjectProperties");
		if (opts.dataObjectFormat) {
			const dof = el(doc, NS.xades, "xades:DataObjectFormat");
			dof.setAttribute("ObjectReference", `#${opts.dataObjectFormat.referenceId}`);
			dof.appendChild(text(doc, NS.xades, "xades:MimeType", opts.dataObjectFormat.mimeType));
			sdop.appendChild(dof);
		}
		if (opts.commitmentType) {
			const cti = el(doc, NS.xades, "xades:CommitmentTypeIndication");
			const ctid = el(doc, NS.xades, "xades:CommitmentTypeId");
			ctid.appendChild(text(doc, NS.xades, "xades:Identifier", `urn:oid:${COMMITMENT_OID[opts.commitmentType]}`));
			cti.appendChild(ctid);
			cti.appendChild(el(doc, NS.xades, "xades:AllSignedDataObjects"));
			sdop.appendChild(cti);
		}
		sp.appendChild(sdop);
	}

	return {
		element: sp,
		id,
		async c14nDigest(alg, c14n) {
			return digest(alg, canonicalize(sp as unknown as Node, c14n));
		},
	};
}

async function buildSigningCertificate(doc: Document, certDer: Uint8Array, digestAlg: HashAlg): Promise<Element> {
	const sc = el(doc, NS.xades, "xades:SigningCertificate");
	const cert = el(doc, NS.xades, "xades:Cert");
	sc.appendChild(cert);

	const cd = el(doc, NS.xades, "xades:CertDigest");
	const dm = el(doc, NS.ds, "ds:DigestMethod");
	dm.setAttribute("Algorithm", DIGEST[digestAlg]);
	cd.appendChild(dm);
	const dv = text(doc, NS.ds, "ds:DigestValue", toBase64(await digest(digestAlg, certDer)));
	cd.appendChild(dv);
	cert.appendChild(cd);

	const parsed = new Certificate({ schema: asn1js.fromBER(toAB(certDer)).result });
	const is = el(doc, NS.xades, "xades:IssuerSerial");
	is.appendChild(text(doc, NS.ds, "ds:X509IssuerName", dnToLdapString(parsed.issuer)));
	is.appendChild(text(doc, NS.ds, "ds:X509SerialNumber", bigintFromAsn1(parsed.serialNumber).toString()));
	cert.appendChild(is);

	return sc;
}

function buildSignaturePolicyIdentifier(
	doc: Document,
	p: { oid: string; digest: Uint8Array; digestAlgorithm: HashAlg; uri?: string },
): Element {
	const spi = el(doc, NS.xades, "xades:SignaturePolicyIdentifier");
	const sid = el(doc, NS.xades, "xades:SignaturePolicyId");
	const id = el(doc, NS.xades, "xades:SigPolicyId");
	id.appendChild(text(doc, NS.xades, "xades:Identifier", `urn:oid:${p.oid}`));
	sid.appendChild(id);
	const hash = el(doc, NS.xades, "xades:SigPolicyHash");
	const dm = el(doc, NS.ds, "ds:DigestMethod");
	dm.setAttribute("Algorithm", DIGEST[p.digestAlgorithm]);
	hash.appendChild(dm);
	hash.appendChild(text(doc, NS.ds, "ds:DigestValue", toBase64(p.digest)));
	sid.appendChild(hash);
	if (p.uri) {
		const q = el(doc, NS.xades, "xades:SigPolicyQualifiers");
		const qq = el(doc, NS.xades, "xades:SigPolicyQualifier");
		qq.appendChild(text(doc, NS.xades, "xades:SPURI", p.uri));
		q.appendChild(qq);
		sid.appendChild(q);
	}
	spi.appendChild(sid);
	return spi;
}

// Format pkijs RDNSequence as RFC 4514 / LDAP string ("CN=...,O=...,C=TR").
// ASN.1 order is root→leaf, LDAP display is leaf→root, so reverse.
function dnToLdapString(name: pkijsNameLike): string {
	const parts: string[] = [];
	for (const tv of name.typesAndValues) {
		const attr = OID_TO_LDAP[tv.type] ?? tv.type;
		const val = (tv.value as { valueBlock: { value: string } }).valueBlock.value;
		parts.push(`${attr}=${escapeDnValue(val)}`);
	}
	return parts.reverse().join(",");
}

type pkijsNameLike = { typesAndValues: { type: string; value: unknown }[] };

const OID_TO_LDAP: Record<string, string> = {
	"2.5.4.3": "CN",
	"2.5.4.4": "SN",
	"2.5.4.5": "SERIALNUMBER",
	"2.5.4.6": "C",
	"2.5.4.7": "L",
	"2.5.4.8": "ST",
	"2.5.4.9": "STREET",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.12": "T",
	"2.5.4.42": "GN",
	"2.5.4.46": "DNQ",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1": "UID",
	"1.2.840.113549.1.9.1": "E",
};

function escapeDnValue(v: string): string {
	// RFC 4514 §2.4: escape leading/trailing space, leading #, and ",+\"<>;=\0".
	return v
		.replace(/\\/g, "\\\\")
		.replace(/"/g, '\\"')
		.replace(/([,+<>;=])/g, "\\$1")
		.replace(/^([# ])/, "\\$1")
		.replace(/ $/, "\\ ");
}

function bigintFromAsn1(i: asn1js.Integer): bigint {
	const hex = Array.from(new Uint8Array(i.valueBlock.valueHexView))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	return hex ? BigInt(`0x${hex}`) : 0n;
}

function toBase64(u8: Uint8Array): string {
	return Buffer.from(u8).toString("base64");
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}

// DOM construction helper — local; 3 uses make it worth it.
function el(doc: Document, ns: string, qname: string): Element {
	return doc.createElementNS(ns, qname);
}
function text(doc: Document, ns: string, qname: string, value: string): Element {
	const e = doc.createElementNS(ns, qname);
	e.appendChild(doc.createTextNode(value));
	return e;
}
