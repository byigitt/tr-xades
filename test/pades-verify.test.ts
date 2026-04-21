import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { padesSign } from "../src/pades-sign.ts";
import { padesVerify } from "../src/pades-verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

async function samplePdf(): Promise<Uint8Array> {
	const doc = await PDFDocument.create();
	const page = doc.addPage([300, 300]);
	page.drawText("tr-esign PAdES test", { x: 40, y: 150, size: 18 });
	return new Uint8Array(await doc.save({ useObjectStreams: false }));
}

test("padesVerify — padesSign ürettiği PDF valid + level BES",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pdf = await samplePdf();
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signed = await padesSign({
			pdf, signer: { pfx, password: "testpass" },
			reason: "Approve", signerName: "Barış",
		});
		const r = await padesVerify(signed);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
		assert.match(r.signer.subject, /CN=Test Signer/);
	});

test("padesVerify — TR P3 policy ile imza EPES raporlar",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pdf = await samplePdf();
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signed = await padesSign({
			pdf, signer: { pfx, password: "testpass" },
			policy: "P3",
			commitmentType: "proof-of-origin",
		});
		const r = await padesVerify(signed);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "EPES");
	});

test("padesVerify — imzalı PDF'in ByteRange içindeki bir baytı değişirse reddet",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pdf = await samplePdf();
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signed = await padesSign({ pdf, signer: { pfx, password: "testpass" } });
		// İlk 50 baytın ortasındaki bir karakteri değiştir (PDF header bölgesi,
		// kesinlikle ByteRange içinde)
		const tampered = new Uint8Array(signed);
		tampered[30] = tampered[30] ^ 0xff;
		const r = await padesVerify(tampered);
		assert.equal(r.valid, false, "tampered PDF reddedilmeli");
	});

test("padesVerify — imzasız PDF reddedilir", async () => {
	const pdf = await samplePdf();
	const r = await padesVerify(pdf);
	assert.equal(r.valid, false);
	if (r.valid) return;
	assert.match(r.reason, /padesVerify:/);
});
