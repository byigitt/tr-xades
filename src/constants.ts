// XML namespace and algorithm URI constants.
// Single source of truth — every other file in this package imports from here.
// Values verified against reference/out/enveloped-bes.xml produced by MA3 2.3.11.8.

export const NS = {
	ds: "http://www.w3.org/2000/09/xmldsig#",
	xades: "http://uri.etsi.org/01903/v1.3.2#",
	xades141: "http://uri.etsi.org/01903/v1.4.1#",
} as const;

export const SIGNED_PROPS_TYPE = "http://uri.etsi.org/01903#SignedProperties";

// Digest algorithms (W3C xmlenc + RFC 4051 / 6931 URIs).
export const DIGEST = {
	"SHA-256": "http://www.w3.org/2001/04/xmlenc#sha256",
	"SHA-384": "http://www.w3.org/2001/04/xmldsig-more#sha384",
	"SHA-512": "http://www.w3.org/2001/04/xmlenc#sha512",
} as const;

// Signature algorithms (xmldsig-more URIs, per MA3 default output).
export const SIGNATURE = {
	"RSA-SHA256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	"RSA-SHA384": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
	"RSA-SHA512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
	"ECDSA-SHA256": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
	"ECDSA-SHA384": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
	"ECDSA-SHA512": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
} as const;

// Canonicalization algorithms.
// Default for UBL-TR e-Fatura is exc-c14n (exclusive, no comments).
// MA3 ships with classic c14n10 as default — override to exc-c14n for TR compliance.
// C14N 1.1 deliberately unsupported: xmldsigjs doesn't implement it and TR
// profile doesn't use it. Reopen when a real need appears.
export const C14N = {
	"c14n10": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
	"c14n10-with-comments": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
	"exc-c14n": "http://www.w3.org/2001/10/xml-exc-c14n#",
	"exc-c14n-with-comments": "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
} as const;

// Transforms (W3C xmldsig).
export const TRANSFORM = {
	"enveloped-signature": "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
	"base64": "http://www.w3.org/2000/09/xmldsig#base64",
	"xpath": "http://www.w3.org/TR/1999/REC-xpath-19991116",
	"xpath-filter2": "http://www.w3.org/2002/06/xmldsig-filter2",
	"xslt": "http://www.w3.org/TR/1999/REC-xslt-19991116",
} as const;

export const ENCODING_BASE64 = "http://www.w3.org/2000/09/xmldsig#base64";

// UBL-TR (e-Fatura) namespace URIs — needed to locate ext:ExtensionContent anchor.
export const UBL = {
	ext: "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
	cbc: "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
	cac: "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
} as const;

// Turkish e-signature policy OIDs (runtime-extracted from MA3 2.3.11.8,
// reference/driver/Ma3Ref.java output). Values cross-checked with
// "Elektronik İmza Kullanım Profilleri Rehberi" (BTK/Kamu SM).
//   P2 — resmi yazışma, P3 — e-Fatura / yapılandırılmış veri, P4 — PDF / unstructured.
export const TR_POLICY_OID = {
	P2: "2.16.792.1.61.0.1.5070.3.1.1",
	P3: "2.16.792.1.61.0.1.5070.3.2.1",
	P4: "2.16.792.1.61.0.1.5070.3.3.1",
} as const;

// Kamu SM defaults.
export const KAMUSM = {
	tsaUrl: "http://tzd.kamusm.gov.tr",
} as const;
