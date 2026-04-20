// CAdES / CMS OID sabitleri (RFC 5652 + ETSI TS 101 733).
// Her değer doğrudan ASN.1 OID string biçiminde — pkijs Attribute.type'a verilir.

// --- CMS ContentType OIDs (RFC 5652 §4) ---
export const CONTENT_TYPE = {
	data: "1.2.840.113549.1.7.1",
	signedData: "1.2.840.113549.1.7.2",
	envelopedData: "1.2.840.113549.1.7.3",
	// ETSI TS 101 733: TSTInfo content type (CAdES-T SignatureTimeStamp token içinde)
	tstInfo: "1.2.840.113549.1.9.16.1.4",
} as const;

// --- Standart signed attributes (RFC 5652 §11) ---
export const SIGNED_ATTR = {
	contentType: "1.2.840.113549.1.9.3",
	messageDigest: "1.2.840.113549.1.9.4",
	signingTime: "1.2.840.113549.1.9.5",
	countersignature: "1.2.840.113549.1.9.6",
} as const;

// --- ETSI CAdES attributes (S/MIME arc 1.2.840.113549.1.9.16.2.*) ---
// Kaynak: ETSI TS 101 733 v2.2.1 §5, RFC 5126 §5.
export const CADES_ATTR = {
	// Signed attributes
	signingCertificate: "1.2.840.113549.1.9.16.2.12", // v1 (SHA-1)
	signingCertificateV2: "1.2.840.113549.1.9.16.2.47", // herhangi hash (tercih edilen)
	signaturePolicyIdentifier: "1.2.840.113549.1.9.16.2.15",
	commitmentTypeIndication: "1.2.840.113549.1.9.16.2.16",
	signerLocation: "1.2.840.113549.1.9.16.2.17",
	signerAttr: "1.2.840.113549.1.9.16.2.18",
	contentHint: "1.2.840.113549.1.9.16.2.4",
	contentIdentifier: "1.2.840.113549.1.9.16.2.7",
	contentTimeStamp: "1.2.840.113549.1.9.16.2.20",

	// Unsigned attributes (XAdES karşılıkları)
	signatureTimeStamp: "1.2.840.113549.1.9.16.2.14",       // CAdES-T
	certificateRefs: "1.2.840.113549.1.9.16.2.21",          // CAdES-C
	revocationRefs: "1.2.840.113549.1.9.16.2.22",           // CAdES-C
	certValues: "1.2.840.113549.1.9.16.2.23",               // CAdES-XL
	revocationValues: "1.2.840.113549.1.9.16.2.24",         // CAdES-XL
	escTimeStamp: "1.2.840.113549.1.9.16.2.25",             // CAdES-X Type 1
	certCRLTimestamp: "1.2.840.113549.1.9.16.2.26",         // CAdES-X Type 2
	archiveTimeStamp: "1.2.840.113549.1.9.16.2.27",         // CAdES-A v1 (deprecated)
	archiveTimeStampV2: "1.2.840.113549.1.9.16.2.48",       // CAdES-A v2 (tercih edilen)
	archiveTimeStampV3: "0.4.0.1733.2.4",                    // CAdES-A v3 (EN 319 122)
} as const;

// NIST hash algorithm OIDs (CMS AlgorithmIdentifier'larda kullanılır).
export const HASH_OID = {
	"SHA-256": "2.16.840.1.101.3.4.2.1",
	"SHA-384": "2.16.840.1.101.3.4.2.2",
	"SHA-512": "2.16.840.1.101.3.4.2.3",
} as const;

// --- ETSI CommitmentType OIDs (RFC 5126 §5.11.1) ---
// XAdES karşılıklarıyla aynı OID arc; tek tabloda tutma duplicate olurdu,
// ama CAdES tarafında ayrı import akışı için burada da referans:
export const CMS_COMMITMENT_OID = {
	"proof-of-origin": "1.2.840.113549.1.9.16.6.1",
	"proof-of-receipt": "1.2.840.113549.1.9.16.6.2",
	"proof-of-delivery": "1.2.840.113549.1.9.16.6.3",
	"proof-of-sender": "1.2.840.113549.1.9.16.6.4",
	"proof-of-approval": "1.2.840.113549.1.9.16.6.5",
	"proof-of-creation": "1.2.840.113549.1.9.16.6.6",
} as const;
