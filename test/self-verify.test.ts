// sign() → verify() round-trip testleri.
// Üç varyant (enveloping, enveloped-UBL, detached) + tampered-negatif.
// Detached'de URI external olduğundan verify() beklendiği gibi URI'yi çözemez;
// bu bekleniyor ve açık bir kural.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { sign } from "../src/sign.ts";
import { verify } from "../src/verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const SAMPLE = join(import.meta.dirname, "..", "reference", "fixtures", "sample-invoice.xml");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

async function pfxBytes(): Promise<Uint8Array> {
	return new Uint8Array(readFileSync(FIXTURE));
}

test("round-trip — enveloping BES",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const xml = await sign({
			input: { bytes: new TextEncoder().encode("<hello>world</hello>"), mimeType: "text/xml" },
			signer: { pfx: await pfxBytes(), password: "testpass" },
			signingTime: new Date("2026-04-20T10:00:00Z"),
		});
		const r = await verify(xml);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
		assert.equal(r.signer.subject, "CN=Test Signer,O=tr-xades test,C=TR");
		assert.equal(r.signedAt?.toISOString(), "2026-04-20T10:00:00.000Z");
	});

test("round-trip — enveloped UBL",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const xml = await sign({
			input: { xml: readFileSync(SAMPLE, "utf8"), placement: "ubl-extension" },
			signer: { pfx: await pfxBytes(), password: "testpass" },
			productionPlace: { city: "Ankara", country: "TR" },
			commitmentType: "proof-of-origin",
		});
		assert.match(xml, /<Invoice\b/);
		assert.match(xml, /<ext:UBLExtensions>[\s\S]*<ds:Signature\b/);
		const r = await verify(xml);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
	});

test("detached — sign shape ok, verify invalid (external URI v0.1 dışı)",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const data = new TextEncoder().encode("contents of external.xml");
		const xml = await sign({
			input: { uri: "external.xml", data, mimeType: "text/xml" },
			signer: { pfx: await pfxBytes(), password: "testpass" },
		});
		assert.match(xml, /<ds:Signature\b/);
		assert.match(xml, /URI="external\.xml"/);
		assert.match(xml, /<xades:DataObjectFormat\b/);
		assert.doesNotMatch(xml, /<ds:Object\b[^>]*Encoding/); // no embedded data

		const r = await verify(xml);
		assert.equal(r.valid, false, "external URI bekleniyor şekilde çözülemez");
		if (r.valid) return;
		assert.match(r.reason, /URI çözümlenemedi|Reference digest/);
	});

test("tampered SignatureValue fails",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		let xml = await sign({
			input: { bytes: new TextEncoder().encode("<x/>"), mimeType: "text/xml" },
			signer: { pfx: await pfxBytes(), password: "testpass" },
		});
		// Flip first significant byte of SignatureValue.
		xml = xml.replace(/<ds:SignatureValue([^>]*)>([A-Za-z0-9+/=])/,
			(_m, attrs, first) => `<ds:SignatureValue${attrs}>${first === "A" ? "B" : "A"}`);
		const r = await verify(xml);
		assert.equal(r.valid, false);
	});
