import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { parseTrailer, writeXrefSection } from "../src/pades-xref.ts";

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
