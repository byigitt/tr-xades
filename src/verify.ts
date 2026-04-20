// XAdES / XMLDSig verifier.
//
// Tek `verify(xml)` — discriminated-union sonuç. XMLDSig §3.2 core validation:
//   1) tüm ds:Reference digest'lerini yeniden hesaplayıp karşılaştır
//   2) ds:SignedInfo c14n + ds:SignatureValue RSA/ECDSA doğrula
// Seviye tespiti: XMLDSig / BES / EPES / T / LT / LTA. Cert chain validation
// v0.1 kapsamında değil (faz 7) — signer bilgisi cert'ten parse edilir.

import { DOMParser } from "@xmldom/xmldom";
import * as asn1js from "asn1js";
import { Certificate } from "pkijs";
import { canonicalize, c14nAlgFromUri, type C14NAlg } from "./c14n.ts";
import { C14N, NS, SIGNATURE, TRANSFORM } from "./constants.ts";
import { importPublicKeyFromCert, verify as cryptoVerify, type HashAlg, type SignatureAlg } from "./crypto.ts";
import { digestReference, type Transform } from "./references.ts";

export type Level = "XMLDSig" | "BES" | "EPES" | "T" | "LT" | "LTA";

export type SignerInfo = {
	subject: string;
	issuer: string;
	serialHex: string;
	notBefore: Date;
	notAfter: Date;
};

export type PerSignatureResult =
	| { signatureId?: string; valid: true; level: Level; signer: SignerInfo; signedAt?: Date; counterSignatures?: SignerInfo[] }
	| { signatureId?: string; valid: false; reason: string };

export type VerifyResult =
	| {
			valid: true; level: Level; signer: SignerInfo; signedAt?: Date;
			counterSignatures?: SignerInfo[];
			// Birden fazla top-level (paralel) imza varsa her birinin sonucu.
			// Tek imza varsa alan yok.
			allSignatures?: PerSignatureResult[];
	  }
	| { valid: false; reason: string; detail?: unknown; allSignatures?: PerSignatureResult[] };

export type ResolverResult = Uint8Array | Node | null | Promise<Uint8Array | Node | null>;
export type Resolver = (uri: string) => ResolverResult;

export type VerifyOptions = {
	// External URI resolver. Çağrılır: detached imza veya in-document fragment
	// olmayan referanslar için. Döndürdüğü bytes/Node digestReference'a beslenir.
	// `null` döner veya eksikse referans "URI çözümlenemedi" hatasıyla reddedilir.
	resolver?: Resolver;
};

export async function verify(xml: string, opts: VerifyOptions = {}): Promise<VerifyResult> {
	try {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const doc: any = new DOMParser().parseFromString(xml, "text/xml");
		const topLevel = collectTopLevelSignatures(doc);
		if (topLevel.length === 0) return invalid("ds:Signature bulunamadı");

		const primary = await verifyOne(doc, topLevel[0], opts);

		if (topLevel.length === 1) return primary;

		const all: PerSignatureResult[] = [];
		for (const s of topLevel) {
			const id: string | undefined = s.getAttribute("Id") ?? undefined;
			const r = s === topLevel[0] ? primary : await verifyOne(doc, s, opts);
			if (r.valid) {
				all.push({
					...(id ? { signatureId: id } : {}),
					valid: true,
					level: r.level,
					signer: r.signer,
					...(r.signedAt ? { signedAt: r.signedAt } : {}),
					...(r.counterSignatures ? { counterSignatures: r.counterSignatures } : {}),
				});
			} else {
				all.push({ ...(id ? { signatureId: id } : {}), valid: false, reason: r.reason });
			}
		}
		return primary.valid ? { ...primary, allSignatures: all } : { ...primary, allSignatures: all };
	} catch (e) {
		return invalid(e instanceof Error ? e.message : "unknown error", e);
	}
}

// Top-level imzalar: xades:CounterSignature içine gömülmemiş olanlar.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function collectTopLevelSignatures(doc: any): any[] {
	const all = doc.getElementsByTagNameNS(NS.ds, "Signature");
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const out: any[] = [];
	for (let i = 0; i < all.length; i++) {
		const s = all.item(i);
		let nested = false;
		for (let n = s.parentNode; n; n = n.parentNode) {
			if (n.nodeType === 1 && n.namespaceURI === NS.xades && n.localName === "CounterSignature") {
				nested = true;
				break;
			}
		}
		if (!nested) out.push(s);
	}
	return out;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function verifyOne(doc: any, sig: any, opts: VerifyOptions): Promise<VerifyResult> {
	try {
		const si = firstChild(sig, NS.ds, "SignedInfo");
		if (!si) return invalid("ds:SignedInfo yok");

		const c14nUri = firstChild(si, NS.ds, "CanonicalizationMethod")?.getAttribute("Algorithm");
		const sigUri = firstChild(si, NS.ds, "SignatureMethod")?.getAttribute("Algorithm");
		if (!c14nUri || !sigUri) return invalid("SignedInfo içinde c14n veya SignatureMethod eksik");
		let c14nAlg: C14NAlg;
		try {
			c14nAlg = c14nAlgFromUri(c14nUri);
		} catch {
			return invalid("desteklenmeyen c14n URI", { uri: c14nUri });
		}
		const sigAlg = sigAlgFromUri(sigUri);
		if (!sigAlg) return invalid("desteklenmeyen signature algorithm", { uri: sigUri });

		const sv = firstChild(sig, NS.ds, "SignatureValue");
		const xcElem = first(sig, NS.ds, "X509Certificate");
		if (!sv || !xcElem) return invalid("ds:SignatureValue veya ds:X509Certificate eksik");

		const sigBytes = base64(text(sv));
		const certDer = base64(text(xcElem));

		// Reference digest'lerini yeniden hesapla.
		const refs = childrenByTag(si, NS.ds, "Reference");
		for (const ref of refs) {
			const err = await verifyReference(doc, sig, ref, opts.resolver);
			if (err) return invalid(err, { referenceUri: ref.getAttribute("URI") });
		}

		// SignedInfo imza doğrulaması.
		const pub = await importPublicKeyFromCert(certDer, sigAlg);
		const siBytes = canonicalize(si, c14nAlg);
		if (!(await cryptoVerify(sigAlg, pub, sigBytes, siBytes))) {
			return invalid("SignedInfo imzası doğrulanamadı");
		}

		const counterSigners: SignerInfo[] = [];
		for (const nested of findCounterSignatures(sig)) {
			const r = await verifyOne(doc, nested, opts);
			if (r.valid) counterSigners.push(r.signer);
		}

		const signedAt = extractSigningTime(sig);
		return {
			valid: true,
			level: detectLevel(sig),
			signer: extractSignerInfo(certDer),
			...(signedAt ? { signedAt } : {}),
			...(counterSigners.length ? { counterSignatures: counterSigners } : {}),
		};
	} catch (e) {
		return invalid(e instanceof Error ? e.message : "unknown error", e);
	}
}

// Find counter-sig ds:Signature'ları: sig/Object/QualifyingProperties/UnsignedProperties/
// UnsignedSignatureProperties/CounterSignature/ds:Signature.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findCounterSignatures(sig: any): any[] {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const out: any[] = [];
	for (const obj of childrenByTag(sig, NS.ds, "Object")) {
		for (const qp of childrenByTag(obj, NS.xades, "QualifyingProperties")) {
			for (const up of childrenByTag(qp, NS.xades, "UnsignedProperties")) {
				for (const usp of childrenByTag(up, NS.xades, "UnsignedSignatureProperties")) {
					for (const cs of childrenByTag(usp, NS.xades, "CounterSignature")) {
						for (const s of childrenByTag(cs, NS.ds, "Signature")) out.push(s);
					}
				}
			}
		}
	}
	return out;
}

// ---- Reference digest verification ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function verifyReference(doc: any, signatureEl: any, ref: any, resolver?: Resolver): Promise<string | null> {
	const uri = ref.getAttribute("URI") ?? "";
	const digestMethod = firstChild(ref, NS.ds, "DigestMethod")?.getAttribute("Algorithm");
	const digestValue = firstChild(ref, NS.ds, "DigestValue");
	if (!digestMethod || !digestValue) return "Reference içinde DigestMethod veya DigestValue eksik";
	const hashAlg = hashAlgFromUri(digestMethod);
	if (!hashAlg) return `desteklenmeyen DigestMethod: ${digestMethod}`;

	const transforms = parseTransforms(firstChild(ref, NS.ds, "Transforms"), signatureEl.getAttribute("Id") ?? undefined);
	if (transforms === null) return "desteklenmeyen Transform Algorithm";

	const data = await resolveUri(doc, uri, resolver);
	if (data === null) return `URI çözümlenemedi: ${uri}`;

	const computed = await digestReference(data, transforms, hashAlg);
	const expected = base64(text(digestValue));
	if (!bytesEqual(computed, expected)) return "Reference digest uyuşmuyor";
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function resolveUri(doc: any, uri: string, resolver?: Resolver): Promise<Node | Uint8Array | null> {
	if (uri === "") return doc.documentElement;
	if (uri.startsWith("#")) return findById(doc, uri.slice(1));
	// External URI (http://, file://, relative path) → resolver gerekir.
	if (!resolver) return null;
	return (await resolver(uri)) ?? null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findById(doc: any, id: string): any {
	// xmldom'un getElementById'ı Id özniteliklerinin DTD tanımı olmadan çalışmaz;
	// tüm elemanları dolaşıp Id eşleşenini bulmak sağlam yol.
	const walker = doc.createTreeWalker
		? doc.createTreeWalker(doc, 1 /* NodeFilter.SHOW_ELEMENT */, null)
		: null;
	if (walker) {
		let n = walker.nextNode();
		while (n) {
			if (n.getAttribute && n.getAttribute("Id") === id) return n;
			n = walker.nextNode();
		}
		return null;
	}
	// Fallback
	const all = doc.getElementsByTagName("*");
	for (let i = 0; i < all.length; i++) if (all[i].getAttribute("Id") === id) return all[i];
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseTransforms(ts: any, signatureId: string | undefined): Transform[] | null {
	if (!ts) return [];
	const out: Transform[] = [];
	for (const t of childrenByTag(ts, NS.ds, "Transform")) {
		const uri = t.getAttribute("Algorithm") ?? "";
		if (uri === TRANSFORM["enveloped-signature"]) {
			out.push({ kind: "enveloped-signature", signatureId });
		} else if (uri === TRANSFORM.base64) {
			out.push({ kind: "base64" });
		} else {
			const c14n = Object.entries(C14N).find(([, v]) => v === uri)?.[0];
			if (c14n) out.push({ kind: "c14n", alg: c14n as C14NAlg });
			else return null;
		}
	}
	return out;
}

// ---- Level / metadata extraction ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function detectLevel(sig: any): Level {
	if (first(sig, NS.xades141, "ArchiveTimeStamp") || first(sig, NS.xades, "ArchiveTimeStamp")) return "LTA";
	if (first(sig, NS.xades, "CompleteCertificateRefs") || first(sig, NS.xades, "CertificateValues")) return "LT";
	if (first(sig, NS.xades, "SignatureTimeStamp")) return "T";
	if (first(sig, NS.xades, "SignaturePolicyIdentifier")) return "EPES";
	if (first(sig, NS.xades, "QualifyingProperties")) return "BES";
	return "XMLDSig";
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractSigningTime(sig: any): Date | undefined {
	const t = first(sig, NS.xades, "SigningTime");
	const s = t ? text(t).trim() : "";
	if (!s) return undefined;
	const d = new Date(s);
	return Number.isNaN(d.getTime()) ? undefined : d;
}

function extractSignerInfo(certDer: Uint8Array): SignerInfo {
	const c = new Certificate({ schema: asn1js.fromBER(toAB(certDer)).result });
	return {
		subject: dnToLdap(c.subject),
		issuer: dnToLdap(c.issuer),
		serialHex: Array.from(new Uint8Array(c.serialNumber.valueBlock.valueHexView))
			.map((b) => b.toString(16).padStart(2, "0"))
			.join(""),
		notBefore: c.notBefore.value,
		notAfter: c.notAfter.value,
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function dnToLdap(name: any): string {
	const map: Record<string, string> = {
		"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU",
		"2.5.4.7": "L", "2.5.4.8": "ST", "1.2.840.113549.1.9.1": "E",
	};
	return name.typesAndValues
		.map((tv: { type: string; value: { valueBlock: { value: string } } }) =>
			`${map[tv.type] ?? tv.type}=${tv.value.valueBlock.value}`)
		.reverse()
		.join(",");
}

// ---- URI↔alg reverse maps ----

function sigAlgFromUri(uri: string): SignatureAlg | null {
	for (const k of Object.keys(SIGNATURE) as SignatureAlg[]) {
		if (SIGNATURE[k] === uri) return k;
	}
	return null;
}
function hashAlgFromUri(uri: string): HashAlg | null {
	if (uri === "http://www.w3.org/2001/04/xmlenc#sha256") return "SHA-256";
	if (uri === "http://www.w3.org/2001/04/xmldsig-more#sha384") return "SHA-384";
	if (uri === "http://www.w3.org/2001/04/xmlenc#sha512") return "SHA-512";
	if (uri === "http://www.w3.org/2001/04/xmldsig-more#sha512") return "SHA-512";
	return null;
}

// ---- tiny DOM helpers ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function first(parent: any, ns: string, local: string): any {
	return parent.getElementsByTagNameNS(ns, local).item(0);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function firstChild(parent: any, ns: string, local: string): any {
	for (let n = parent.firstChild; n; n = n.nextSibling) {
		if (n.nodeType === 1 && n.namespaceURI === ns && n.localName === local) return n;
	}
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function childrenByTag(parent: any, ns: string, local: string): any[] {
	const out: unknown[] = [];
	for (let n = parent.firstChild; n; n = n.nextSibling) {
		if (n.nodeType === 1 && n.namespaceURI === ns && n.localName === local) out.push(n);
	}
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return out as any[];
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function text(el: any): string {
	return (el.textContent ?? "").trim();
}

function base64(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "base64"));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}

function invalid(reason: string, detail?: unknown): VerifyResult {
	return detail === undefined ? { valid: false, reason } : { valid: false, reason, detail };
}
