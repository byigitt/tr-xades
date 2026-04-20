import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { sign } from "../src/sign.ts";
import { verify } from "../src/verify.ts";

const REF_OUT = join(import.meta.dirname, "..", "reference", "out");
const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const SAMPLE = join(import.meta.dirname, "..", "reference", "fixtures", "sample-invoice.xml");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();
function readOpt(p: string): string | null { try { return readFileSync(p, "utf8"); } catch { return null; } }

test("verify — self-sign + verify (enveloping BES)",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const xml = await sign({
			input: { bytes: new TextEncoder().encode("<hi/>"), mimeType: "text/xml" },
			signer: { pfx, password: "testpass" },
			signingTime: new Date("2026-04-20T09:00:00Z"),
		});
		const r = await verify(xml);
		assert.equal(r.valid, true);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
		assert.equal(r.signer.subject, "CN=Test Signer,O=tr-xades test,C=TR");
		assert.equal(r.signedAt?.toISOString(), "2026-04-20T09:00:00.000Z");
	});

test("verify — self-sign + verify (UBL enveloped BES)",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const xml = await sign({
			input: { xml: readFileSync(SAMPLE, "utf8"), placement: "ubl-extension" },
			signer: { pfx, password: "testpass" },
		});
		const r = await verify(xml);
		assert.equal(r.valid, true, r.valid ? "" : `reason: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
	});

test("verify — tampered SignatureValue fails",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		let xml = await sign({
			input: { bytes: new TextEncoder().encode("<x/>"), mimeType: "text/xml" },
			signer: { pfx, password: "testpass" },
		});
		// Flip a byte inside SignatureValue.
		xml = xml.replace(/<ds:SignatureValue([^>]*)>([A-Za-z0-9+/=])/,
			(_m, attrs, first) => `<ds:SignatureValue${attrs}>${first === "A" ? "B" : "A"}`);
		const r = await verify(xml);
		assert.equal(r.valid, false);
	});

test("verify — MA3 reference fixture (enveloping-bes.xml)", async () => {
	const xml = readOpt(join(REF_OUT, "enveloping-bes.xml"));
	if (!xml) { console.log("SKIP: run reference/run.sh to produce fixtures"); return; }
	const r = await verify(xml);
	assert.equal(r.valid, true, r.valid ? "" : `MA3 enveloping fixture failed: ${r.reason}`);
	if (!r.valid) return;
	assert.equal(r.level, "BES");
	assert.equal(r.signer.subject, "CN=Test Signer,O=tr-xades test,C=TR");
});
