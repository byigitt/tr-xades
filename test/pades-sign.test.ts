import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { PDFDocument } from "pdf-lib";
import { padesSign } from "../src/pades-sign.ts";
import { readByteRange, findContentsPlaceholder, extractByteRangeBytes } from "../src/pades-core.ts";
import { CONTENT_TYPE } from "../src/cades-constants.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

async function samplePdf(): Promise<Uint8Array> {
	const doc = await PDFDocument.create();
	const page = doc.addPage([300, 300]);
	page.drawText("PAdES test document", { x: 50, y: 150, size: 18 });
	// useObjectStreams:false — @signpdf classic xref tablosu bekler
	return new Uint8Array(await doc.save({ useObjectStreams: false }));
}

test("padesSign — PDF'e /SubFilter /ETSI.CAdES.detached imza dictionary eklenir",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pdf = await samplePdf();
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signed = await padesSign({
			pdf, signer: { pfx, password: "testpass" },
			reason: "Test", signerName: "Barış",
		});

		const str = Buffer.from(signed).toString("latin1");
		assert.match(str, /\/SubFilter\s*\/ETSI\.CAdES\.detached/, "SubFilter beklenen");
		assert.match(str, /\/Filter\s*\/Adobe\.PPKLite/, "Filter PPKLite");
		assert.match(str, /\/ByteRange\s*\[0\s+\d+\s+\d+\s+\d+\]/, "ByteRange dolu");
		assert.match(str, /\/AcroForm\s/, "AcroForm eklendi");
	});

test("padesSign — /Contents içindeki CMS geçerli bir SignedData",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pdf = await samplePdf();
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signed = await padesSign({
			pdf, signer: { pfx, password: "testpass" },
			reason: "CMS validity test",
		});

		// /Contents hex bölgesini çıkar, trailing zero'ları at, DER parse
		const { start, end } = findContentsPlaceholder(signed);
		const hex = Buffer.from(signed.subarray(start, end)).toString("latin1");
		const trimmed = hex.replace(/0+$/, "");
		const cmsDer = new Uint8Array(Buffer.from(trimmed + (trimmed.length % 2 ? "0" : ""), "hex"));
		assert.ok(cmsDer.length > 100, `CMS DER boyutu anlamlı olmalı (got ${cmsDer.length})`);

		const ab = new ArrayBuffer(cmsDer.byteLength);
		new Uint8Array(ab).set(cmsDer);
		const asn = asn1js.fromBER(ab);
		assert.notEqual(asn.offset, -1, "CMS DER parse edilebilmeli");
		const ci = new pkijs.ContentInfo({ schema: asn.result });
		assert.equal(ci.contentType, CONTENT_TYPE.signedData);
		const sd = new pkijs.SignedData({ schema: ci.content });
		assert.equal(sd.signerInfos.length, 1, "tek signerInfo");
		// PAdES detached: eContent yok
		assert.equal(sd.encapContentInfo.eContent, undefined, "eContent olmamalı (detached)");
	});

test("padesSign — ByteRange signed PDF'in /Contents DIŞINI kapsar",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pdf = await samplePdf();
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signed = await padesSign({ pdf, signer: { pfx, password: "testpass" } });

		const br = readByteRange(signed);
		const { start, end } = findContentsPlaceholder(signed);
		// ByteRange = [a, b, c, d] → dışlanan [b..c). start '<' sonrası,
		// so '<' pozisyonu = start - 1. b uzunluk = '<' pozisyonuna kadar.
		assert.equal(br[1], start - 1, "ByteRange[1] = '<' offset");
		assert.equal(br[2], end + 1, "ByteRange[2] = '>' sonrası offset");
		assert.equal(br[0] + br[1] + (end - start + 2) + br[3], signed.length, "kapsam toplamı = dosya boyu");

		// Extract ve hash et
		const data = extractByteRangeBytes(signed, br);
		assert.equal(data.length, br[1] + br[3]);
	});
