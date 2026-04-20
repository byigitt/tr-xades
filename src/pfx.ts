// PKCS#12 (PFX) loader. Returns raw PKCS#8 private key bytes + end-entity cert
// + any additional chain certs, all as DER Uint8Arrays. Key import to a
// CryptoKey is deferred — crypto.ts binds the hash at WebCrypto importKey time.

import * as asn1js from "asn1js";
import { Crypto } from "@peculiar/webcrypto";
import * as pkijs from "pkijs";

// Register a crypto engine so pkijs can run password MACs / bag decryption.
const webcrypto = new Crypto();
pkijs.setEngine(
	"webcrypto",
	new pkijs.CryptoEngine({
		name: "webcrypto",
		crypto: webcrypto,
		subtle: webcrypto.subtle,
	}) as unknown as pkijs.ICryptoEngine,
);

export type PfxBundle = {
	privateKey: { pkcs8: Uint8Array; algorithm: "RSA" | "EC" };
	certificate: Uint8Array; // end-entity, DER
	chain: Uint8Array[]; // additional certs in the bag, DER
};

export async function loadPfx(bytes: Uint8Array, password: string): Promise<PfxBundle> {
	const pwdBuf = new TextEncoder().encode(password).buffer as ArrayBuffer;

	const asn = asn1js.fromBER(toAB(bytes));
	if (asn.offset === -1) throw new Error("PFX: ASN.1 parse failed");
	const pfx = new pkijs.PFX({ schema: asn.result });
	await pfx.parseInternalValues({ password: pwdBuf, checkIntegrity: true });

	const authSafe = pfx.parsedValue?.authenticatedSafe;
	if (!authSafe) throw new Error("PFX: authenticatedSafe missing");
	// Provide a password entry per safeContents (AuthenticatedSafe can contain
	// multiple, each potentially encrypted). Most bundles have 2: certs + keys.
	const safeList = authSafe.parsedValue?.safeContents?.length ?? 2;
	await authSafe.parseInternalValues({
		safeContents: Array.from({ length: safeList }, () => ({ password: pwdBuf })),
	});

	const certs: Uint8Array[] = [];
	let pkcs8: Uint8Array | undefined;

	for (const safe of authSafe.parsedValue?.safeContents ?? []) {
		for (const bag of safe.value.safeBags ?? []) {
			const v = bag.bagValue;
			if (v instanceof pkijs.CertBag) {
				const cert = v.parsedValue as pkijs.Certificate;
				certs.push(new Uint8Array(cert.toSchema().toBER()));
			} else if (v instanceof pkijs.PKCS8ShroudedKeyBag) {
				// parseInternalValues is typed protected but is the public runtime API.
				await (v as unknown as { parseInternalValues(p: { password: ArrayBuffer }): Promise<void> })
					.parseInternalValues({ password: pwdBuf });
				const pki = v.parsedValue;
				if (!pki) throw new Error("PFX: shrouded key decrypt failed");
				pkcs8 = new Uint8Array(pki.toSchema().toBER());
			} else if (v instanceof pkijs.KeyBag) {
				pkcs8 = new Uint8Array(v.toSchema().toBER());
			}
		}
	}

	if (!pkcs8) throw new Error("PFX: no private key bag");
	if (certs.length === 0) throw new Error("PFX: no certificates");

	const ordered = orderChain(certs);
	return {
		privateKey: { pkcs8, algorithm: detectKeyAlgorithm(pkcs8) },
		certificate: ordered[0]!,
		chain: ordered.slice(1),
	};
}

// Peek at PrivateKeyInfo.privateKeyAlgorithm.algorithm OID.
function detectKeyAlgorithm(pkcs8: Uint8Array): "RSA" | "EC" {
	const pki = asn1js.fromBER(toAB(pkcs8)).result as asn1js.Sequence;
	const algSeq = pki.valueBlock.value[1] as asn1js.Sequence;
	const oid = algSeq.valueBlock.value[0] as asn1js.ObjectIdentifier;
	const s = oid.valueBlock.toString();
	if (s === "1.2.840.113549.1.1.1") return "RSA";
	if (s === "1.2.840.10045.2.1") return "EC";
	throw new Error(`PFX: unsupported private key algorithm ${s}`);
}

// Put the end-entity cert (not issuer of any sibling) first. Single-cert
// bundles and self-signed fixtures pass through unchanged.
function orderChain(certs: Uint8Array[]): Uint8Array[] {
	if (certs.length < 2) return certs;
	const parsed = certs.map((d) => new pkijs.Certificate({ schema: asn1js.fromBER(toAB(d)).result }));
	const subjects = parsed.map((c) => dnKey(c, false));
	const issuers = parsed.map((c) => dnKey(c, true));
	const leafIdx = parsed.findIndex((_, i) => !issuers.includes(subjects[i]!));
	if (leafIdx <= 0) return certs;
	return [certs[leafIdx]!, ...certs.filter((_, i) => i !== leafIdx)];
}

function dnKey(c: pkijs.Certificate, issuer = false): string {
	const schema = (issuer ? c.issuer : c.subject).toSchema();
	return Buffer.from(new Uint8Array(schema.toBER())).toString("base64");
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
