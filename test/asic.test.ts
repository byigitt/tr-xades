import { test } from "node:test";
import assert from "node:assert/strict";
import { createAsic, readAsic } from "../src/asic.ts";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

// ZIP local file header: sig (PK\x03\x04) 4 + fields 26 = 30 bayt,
// sonra file name. ETSI EN 319 162-1 §A.1 ilk entry "mimetype" STORED olmalı.
function firstEntryName(zip: Uint8Array): string {
	// offset 26..27 = filename length (LE uint16)
	const nameLen = zip[26]! | (zip[27]! << 8);
	return dec(zip.slice(30, 30 + nameLen));
}
function firstEntryCompression(zip: Uint8Array): number {
	// offset 8..9 = compression method (LE uint16). 0 = STORED, 8 = DEFLATE.
	return zip[8]! | (zip[9]! << 8);
}
function findMimetypeContent(zip: Uint8Array): string {
	// mimetype STORED; içerik 30+name len sonra direkt.
	const nameLen = zip[26]! | (zip[27]! << 8);
	const compSize = zip[18]! | (zip[19]! << 8) | (zip[20]! << 16) | (zip[21]! << 24);
	return dec(zip.slice(30 + nameLen, 30 + nameLen + compSize));
}

test("createAsic / readAsic — ASiC-S with XAdES signature round-trip", () => {
	const zip = createAsic({
		type: "asic-s",
		data: { name: "document.txt", bytes: enc("hello world") },
		signature: { bytes: enc("<ds:Signature/>"), format: "xades" },
	});

	// EN 319 162-1 §A.1: mimetype first, STORED.
	assert.equal(firstEntryName(zip), "mimetype");
	assert.equal(firstEntryCompression(zip), 0, "mimetype STORED (no compression) olmalı");
	assert.equal(findMimetypeContent(zip), "application/vnd.etsi.asic-s+zip");

	const back = readAsic(zip);
	assert.equal(back.type, "asic-s");
	assert.equal(back.dataFiles.length, 1);
	assert.equal(back.dataFiles[0]!.name, "document.txt");
	assert.equal(dec(back.dataFiles[0]!.bytes), "hello world");
	assert.equal(back.signatures.length, 1);
	assert.equal(back.signatures[0]!.name, "META-INF/signatures.xml");
	assert.equal(back.signatures[0]!.format, "xades");
	assert.equal(back.manifests.length, 0);
});

test("createAsic / readAsic — ASiC-S with CAdES signature round-trip", () => {
	const zip = createAsic({
		type: "asic-s",
		data: { name: "data.bin", bytes: new Uint8Array([1, 2, 3, 4]) },
		signature: { bytes: new Uint8Array([0x30, 0x80]), format: "cades" },
	});

	assert.equal(findMimetypeContent(zip), "application/vnd.etsi.asic-s+zip");

	const back = readAsic(zip);
	assert.equal(back.signatures[0]!.name, "META-INF/signature.p7s");
	assert.equal(back.signatures[0]!.format, "cades");
});

test("createAsic / readAsic — ASiC-E multi-file + manifest round-trip", () => {
	const zip = createAsic({
		type: "asic-e",
		dataFiles: [
			{ name: "f1.txt", bytes: enc("one") },
			{ name: "f2.txt", bytes: enc("two") },
			{ name: "f3.txt", bytes: enc("three") },
		],
		signatures: [
			{ bytes: enc("<sig1/>"), format: "xades", manifest: enc("<manifest1/>") },
		],
	});

	assert.equal(findMimetypeContent(zip), "application/vnd.etsi.asic-e+zip");

	const back = readAsic(zip);
	assert.equal(back.type, "asic-e");
	assert.equal(back.dataFiles.length, 3);
	assert.deepEqual(back.dataFiles.map((f) => f.name).sort(), ["f1.txt", "f2.txt", "f3.txt"]);
	assert.equal(back.signatures.length, 1);
	assert.equal(back.signatures[0]!.name, "META-INF/signatures001.xml");
	assert.equal(back.manifests.length, 1);
	assert.equal(back.manifests[0]!.name, "META-INF/ASiCManifest001.xml");
	assert.equal(dec(back.manifests[0]!.bytes), "<manifest1/>");
});

test("readAsic — bilinmeyen mimetype red", () => {
	// Mimetype'ı olmayan bir ASiC-S inşa edelim: createAsic içinde mimetype'ı
	// sabit olduğu için bunu yapmak için zipSync'i kendimiz çağırmaya gerek yok;
	// yalnızca dışarıdan gelen bozuk bir zip ile test ederiz.
	// Yoksa mimetype yoksa readAsic hata atar.
	const bad = new Uint8Array([0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
	assert.throws(() => readAsic(bad));
});
