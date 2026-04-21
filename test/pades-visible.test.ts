import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { padesSign } from "../src/pades-sign.ts";
import { padesVerify } from "../src/pades-verify.ts";
import { buildAppearance } from "../src/pades-visible.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

async function samplePdf(): Promise<Uint8Array> {
	const doc = await PDFDocument.create();
	doc.addPage([400, 400]).drawText("doc", { x: 50, y: 200, size: 16 });
	return new Uint8Array(await doc.save({ useObjectStreams: false }));
}

test("buildAppearance — çerçeve + metin PDF operator stream üretir", () => {
	const r = buildAppearance({
		page: 1,
		rect: [0, 0, 200, 100],
		text: "Line1\nLine2",
		fontSize: 12,
	});
	assert.deepEqual(r.bbox, [0, 0, 200, 100]);
	const body = new TextDecoder().decode(r.content);
	assert.match(body, /^q/);        // state save başlangıçta
	assert.match(body, /\nQ$/);      // state restore sonda
	assert.match(body, /re S/);      // border rectangle stroke
	assert.match(body, /\/F1 12 Tf/);
	assert.match(body, /\(Line1\) Tj/);
	assert.match(body, /\(Line2\) Tj/);
});

test("buildAppearance — parantez ve ters eğik çizgi PDF string escape",
	() => {
		const r = buildAppearance({
			page: 1, rect: [0, 0, 100, 50],
			text: "CN=Ahmet (Yılmaz) \\Ltd",
		});
		const body = new TextDecoder().decode(r.content);
		// "(" → "\(", ")" → "\)", "\" → "\\"
		assert.match(body, /\(CN=Ahmet \\\(Y\u0131lmaz\\\) \\\\Ltd\) Tj/);
	});

test("padesSign visibleSignature — /AP /N + /XObject Form + /Rect PDF'te mevcut",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pdf = await samplePdf();
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signed = await padesSign({
			pdf, signer: { pfx, password: "testpass" },
			signerName: "Test Signer",
			visibleSignature: {
				page: 1,
				rect: [50, 50, 250, 110],
				text: "Test Signer\n21 Nisan 2026\nOnayland\u0131",
				fontSize: 10,
			},
		});

		const s = Buffer.from(signed).toString("latin1");
		assert.match(s, /\/AP\s*<<\s*\/N\s+\d+\s+\d+\s+R\s*>>/, "/AP /N ref");
		assert.match(s, /\/Type\s*\/XObject\s*\/Subtype\s*\/Form/, "XObject Form");
		assert.match(s, /\/BBox\s*\[0\s+0\s+200\s+60\]/, "bbox");
		assert.match(s, /\/Rect\s*\[50\s+50\s+250\s+110\]/, "rect");
		assert.match(s, /\/BaseFont\s*\/Helvetica/, "font");

		// İmza hâlâ geçerli — görünür kısım ByteRange dışında eklenmedi
		const r = await padesVerify(signed);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
	});
