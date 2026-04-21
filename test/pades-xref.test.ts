import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { loadPfx } from "../src/pfx.ts";
import { padesSign } from "../src/pades-sign.ts";
import { padesUpgrade } from "../src/pades-upgrade.ts";
import { padesVerify } from "../src/pades-verify.ts";
import { parseTrailer, writeXrefSection } from "../src/pades-xref.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();
const live = process.env.TR_XADES_LIVE_TSA === "1";

async function samplePdf(useObjectStreams: boolean): Promise<Uint8Array> {
	const doc = await PDFDocument.create();
	doc.addPage([200, 200]).drawText(useObjectStreams ? "xref stream" : "classic xref");
	return new Uint8Array(await doc.save({ useObjectStreams }));
}

test("parseTrailer — classic trailer PDF", async () => {
	const pdf = await samplePdf(false);
	const trailer = parseTrailer(pdf);
	assert.equal(trailer.kind, "classic");
	assert.match(trailer.root, /^\d+\s+\d+\s+R$/);
	assert.ok(trailer.size > 0);
	assert.ok(trailer.startxref > 0);
});

test("parseTrailer — xref stream PDF", async () => {
	const pdf = await samplePdf(true);
	const trailer = parseTrailer(pdf);
	assert.equal(trailer.kind, "xref-stream");
	assert.match(trailer.root, /^\d+\s+\d+\s+R$/);
	assert.ok(trailer.size > 0);
	assert.ok(trailer.startxref > 0);
});

test("writeXrefSection — classic incremental xref block üretir", () => {
	const out = writeXrefSection(
		[[8, 641], [9, 712], [12, 800]],
		{ size: 13, root: "2 0 R", info: "3 0 R", prev: 515, startxref: 999 },
	);
	assert.match(out, /^xref\n0 1\n0000000000 65535 f /);
	assert.match(out, /8 2\n0000000641 00000 n \n0000000712 00000 n /);
	assert.match(out, /12 1\n0000000800 00000 n /);
	assert.match(out, /trailer\n<< \/Size 13 \/Root 2 0 R \/Info 3 0 R \/Prev 515 >>/);
	assert.match(out, /startxref\n999\n%%EOF\n$/);
});

test("xref-stream PDF — padesSign → padesVerify round-trip", { skip: !hasPfx && "fixture yok" }, async () => {
	const pdf = await samplePdf(true);
	assert.equal(Buffer.from(pdf).toString("latin1").includes("/Type /XRef"), true, "input xref-stream olmalı");
	const pfx = new Uint8Array(readFileSync(FIXTURE));
	const signed = await padesSign({
		pdf,
		signer: { pfx, password: "testpass" },
		visibleSignature: { page: 1, rect: [20, 20, 120, 60], text: "xref stream" },
	});
	const r = await padesVerify(signed);
	assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
	if (!r.valid) return;
	assert.equal(r.level, "BES");
});

test("xref-stream PDF — padesUpgrade LT round-trip", { skip: !hasPfx && "fixture yok" }, async () => {
	const pdf = await samplePdf(true);
	const pfx = new Uint8Array(readFileSync(FIXTURE));
	const bundle = await loadPfx(pfx, "testpass");
	const signed = await padesSign({ pdf, signer: { pfx, password: "testpass" } });
	const lt = await padesUpgrade({ pdf: signed, to: "LT", chain: [bundle.certificate, ...bundle.chain] });
	const r = await padesVerify(lt);
	assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
	if (!r.valid) return;
	assert.equal(r.level, "LT");
});

test("xref-stream PDF — padesUpgrade LTA round-trip (live TSA)",
	{ skip: (!hasPfx || !live) && "needs fixture + TR_XADES_LIVE_TSA=1" },
	async () => {
		const pdf = await samplePdf(true);
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const bundle = await loadPfx(pfx, "testpass");
		const signed = await padesSign({ pdf, signer: { pfx, password: "testpass" } });
		const lt = await padesUpgrade({ pdf: signed, to: "LT", chain: [bundle.certificate, ...bundle.chain] });
		const lta = await padesUpgrade({ pdf: lt, to: "LTA", tsa: { url: "https://freetsa.org/tsr" } });
		const r = await padesVerify(lta);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "LTA");
	});
