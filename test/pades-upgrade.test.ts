import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { padesSign } from "../src/pades-sign.ts";
import { padesUpgrade } from "../src/pades-upgrade.ts";
import { padesVerify } from "../src/pades-verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();
const live = process.env.TR_XADES_LIVE_TSA === "1";

async function samplePdf(): Promise<Uint8Array> {
	const doc = await PDFDocument.create();
	doc.addPage([200, 200]).drawText("T upgrade", { x: 50, y: 100, size: 16 });
	return new Uint8Array(await doc.save({ useObjectStreams: false }));
}

test("padesUpgrade — PAdES B-B → B-T (live FreeTSA)",
	{ skip: (!hasPfx || !live) && "needs fixture + TR_XADES_LIVE_TSA=1" },
	async () => {
		const pdf = await samplePdf();
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const bes = await padesSign({ pdf, signer: { pfx, password: "testpass" } });
		const t = await padesUpgrade({ pdf: bes, to: "T", tsa: { url: "https://freetsa.org/tsr" } });

		// Length-preserving: aynı placeholder, aynı PDF boyutu
		assert.equal(t.length, bes.length, "padesUpgrade byte-length koruma");
		const r = await padesVerify(t);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "T");
	});
