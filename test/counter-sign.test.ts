import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { counterSign } from "../src/counter-sign.ts";
import { sign } from "../src/sign.ts";
import { verify } from "../src/verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("counterSign — parent ds:Signature'a ikinci imzacı ekler",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const parent = await sign({
			input: { bytes: new TextEncoder().encode("<doc/>"), mimeType: "text/xml" },
			signer: { pfx, password: "testpass" },
		});
		const withCounter = await counterSign({
			xml: parent,
			signer: { pfx, password: "testpass" },
			signingTime: new Date("2026-04-20T13:00:00Z"),
		});

		// Yapı: parent sig'in UnsignedSignatureProperties'inde CounterSignature
		assert.match(withCounter, /<xades:UnsignedSignatureProperties\b/);
		assert.match(withCounter, /<xades:CounterSignature\b/);
		// Counter-sig Reference'ı parent'ın SignatureValue'suna işaret etmeli
		assert.match(withCounter, /Type="http:\/\/uri\.etsi\.org\/01903#CountersignedSignature"/);
		// Parent SignatureValue'ya Id eklenmiş olmalı
		assert.match(withCounter, /<ds:SignatureValue[^>]*Id="Signature-Value-Id-/);

		// verify() parent'ı doğrular ve counterSignatures dizisinde counter-sig'in signer info'sunu verir.
		const r = await verify(withCounter);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.ok(r.counterSignatures && r.counterSignatures.length === 1, "1 counter-sig bekleniyor");
		assert.equal(r.counterSignatures![0].subject, "CN=Test Signer,O=tr-xades test,C=TR");
	});
