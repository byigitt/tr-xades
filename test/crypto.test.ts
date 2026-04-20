import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { digest, importPrivateKey, importPublicKeyFromCert, sign, verify } from "../src/crypto.ts";
import { loadPfx } from "../src/pfx.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasFixture = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("digest — known SHA-256 vector", async () => {
	const out = await digest("SHA-256", new TextEncoder().encode("abc"));
	assert.equal(
		Buffer.from(out).toString("hex"),
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	);
});

test("sign + verify RSA round-trip with PFX fixture",
	{ skip: !hasFixture && "run reference/run.sh" },
	async () => {
		const bundle = await loadPfx(new Uint8Array(readFileSync(FIXTURE)), "testpass");
		const priv = await importPrivateKey(bundle.privateKey.pkcs8, "RSA-SHA256");
		const pub = await importPublicKeyFromCert(bundle.certificate, "RSA-SHA256");
		const data = new TextEncoder().encode("hello tr-xades");
		const sig = await sign("RSA-SHA256", priv, data);
		assert.equal(sig.byteLength, 256, "RSA-2048 signature should be 256 bytes");
		assert.ok(await verify("RSA-SHA256", pub, sig, data), "signature must verify");

		data[0] ^= 1;
		assert.equal(await verify("RSA-SHA256", pub, sig, data), false, "tampered data must fail");
	},
);
