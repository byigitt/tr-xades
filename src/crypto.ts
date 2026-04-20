// WebCrypto wrappers for digest / sign / verify. Node 20+'nin global `crypto.subtle`'ı
// kullanılır. Key import burada yapılır çünkü RSASSA-PKCS1-v1_5'te hash importKey anında
// CryptoKey'e bound oluyor (ECDSA'da değil ama tek yol tutmak için her ikisini de
// signatureAlg'a göre import ediyoruz).

import * as asn1js from "asn1js";
import { Certificate } from "pkijs";

export type HashAlg = "SHA-256" | "SHA-384" | "SHA-512";
export type SignatureAlg =
	| "RSA-SHA256" | "RSA-SHA384" | "RSA-SHA512"
	| "ECDSA-SHA256" | "ECDSA-SHA384" | "ECDSA-SHA512";

const subtle = globalThis.crypto.subtle;

export async function digest(alg: HashAlg, data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await subtle.digest(alg, data as BufferSource));
}

export async function importPrivateKey(pkcs8: Uint8Array, alg: SignatureAlg): Promise<CryptoKey> {
	return subtle.importKey("pkcs8", pkcs8 as BufferSource, algParams(alg), false, ["sign"]);
}

export async function importPublicKeyFromCert(certDer: Uint8Array, alg: SignatureAlg): Promise<CryptoKey> {
	// Re-serialize SubjectPublicKeyInfo from the X.509 — WebCrypto importKey
	// wants SPKI, not the full Certificate.
	const cert = new Certificate({ schema: asn1js.fromBER(toAB(certDer)).result });
	const spki = new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER());
	return subtle.importKey("spki", spki as BufferSource, algParams(alg), false, ["verify"]);
}

export async function sign(alg: SignatureAlg, key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await subtle.sign(signParams(alg), key, data as BufferSource));
}

export async function verify(alg: SignatureAlg, key: CryptoKey, sig: Uint8Array, data: Uint8Array): Promise<boolean> {
	return subtle.verify(signParams(alg), key, sig as BufferSource, data as BufferSource);
}

function algParams(alg: SignatureAlg): RsaHashedImportParams | EcKeyImportParams {
	if (alg.startsWith("RSA-")) {
		return { name: "RSASSA-PKCS1-v1_5", hash: hashOf(alg) };
	}
	return { name: "ECDSA", namedCurve: curveFor(hashOf(alg)) };
}

function signParams(alg: SignatureAlg): AlgorithmIdentifier | EcdsaParams {
	if (alg.startsWith("RSA-")) return { name: "RSASSA-PKCS1-v1_5" };
	return { name: "ECDSA", hash: hashOf(alg) };
}

function hashOf(alg: SignatureAlg): HashAlg {
	return alg.slice(alg.indexOf("-") + 1).replace(/(\d+)$/, "-$1") as HashAlg;
}

// WebCrypto ECDSA importKey requires a specific curve. We match SHA size to
// the common NIST curve (P-256 / P-384 / P-521). For non-matching bundles
// the caller should import the key themselves.
function curveFor(hash: HashAlg): string {
	return hash === "SHA-256" ? "P-256" : hash === "SHA-384" ? "P-384" : "P-521";
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
