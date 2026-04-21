// PAdES primitives — PDF incremental update placeholder + ByteRange + splice.
// ETSI EN 319 142-1 §5.3: /SubFilter /ETSI.CAdES.detached, CMS SignedData
// detached, eContent yok; messageDigest = hash(ByteRange bytes).
//
// Placeholder ekleme @signpdf/placeholder-plain ile — string-tabanlı incremental
// update (xref extend, new trailer, /Prev eski xref). ByteRange ve /Contents
// scanning elle yapıldı (küçük işlem, bağımlılık azaltır).

import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SUBFILTER_ETSI_CADES_DETACHED } from "@signpdf/utils";

export type PlaceholderOptions = {
	reason?: string;
	location?: string;
	contactInfo?: string;
	signerName?: string;
	/** /Contents placeholder boyutu (bayt). 16384 çoğu CMS'e yeter. */
	signatureSize?: number;
};

export function addSignaturePlaceholder(pdfIn: Uint8Array, opts: PlaceholderOptions = {}): Uint8Array {
	const raw = plainAddPlaceholder({
		pdfBuffer: Buffer.from(pdfIn),
		reason: opts.reason ?? "Signing",
		location: opts.location ?? "",
		contactInfo: opts.contactInfo ?? "",
		name: opts.signerName ?? "",
		signatureLength: opts.signatureSize ?? 16384,
		subFilter: SUBFILTER_ETSI_CADES_DETACHED,
	});
	// @signpdf /ByteRange için placeholder yazıyor ([0 /********** ...]);
	// asıl değerleri /Contents pozisyonundan hesaplayıp aynı genişlikle yaz.
	return writeByteRange(new Uint8Array(raw));
}

function writeByteRange(pdf: Uint8Array): Uint8Array {
	const str = toLatin1(pdf);
	const brMatch = /\/ByteRange\s*\[[^\]]*\]/.exec(str);
	if (!brMatch) throw new Error("pades: /ByteRange placeholder bulunamadı");
	const brStart = brMatch.index;
	const brLen = brMatch[0].length;

	const { start: hexStart, end: hexEnd } = findContentsPlaceholder(pdf);
	// '<' position = hexStart-1; '>' position = hexEnd.
	const a = 0;
	const b = hexStart - 1;              // bytes [0..b) — '<' dahil değil
	const c = hexEnd + 1;                // '>' sonrası
	const d = pdf.length - c;
	const actual = `/ByteRange [${a} ${b} ${c} ${d}]`;
	if (actual.length > brLen) throw new Error(`pades: /ByteRange ${actual.length} > placeholder ${brLen}`);
	const padded = actual.padEnd(brLen, " ");
	const out = new Uint8Array(pdf);
	for (let i = 0; i < padded.length; i++) out[brStart + i] = padded.charCodeAt(i);
	return out;
}

/** /ByteRange [a b c d] değerlerini okur. */
export function readByteRange(pdf: Uint8Array): [number, number, number, number] {
	const str = toLatin1(pdf);
	const m = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/.exec(str);
	if (!m) throw new Error("pades: /ByteRange bulunamadı");
	return [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
}

/** ByteRange = [a, b, c, d] → bytes [a..a+b) ++ [c..c+d). CMS messageDigest input'u. */
export function extractByteRangeBytes(
	pdf: Uint8Array,
	br: [number, number, number, number],
): Uint8Array {
	const [a, b, c, d] = br;
	const out = new Uint8Array(b + d);
	out.set(pdf.subarray(a, a + b), 0);
	out.set(pdf.subarray(c, c + d), b);
	return out;
}

/** /Contents<HEX> bölgesinin hex içerik sınırları (exclusive <, >). */
export function findContentsPlaceholder(pdf: Uint8Array): { start: number; end: number } {
	const str = toLatin1(pdf);
	const idx = str.indexOf("/Contents");
	if (idx < 0) throw new Error("pades: /Contents bulunamadı");
	const lt = str.indexOf("<", idx);
	if (lt < 0) throw new Error("pades: /Contents '<' bulunamadı");
	const gt = str.indexOf(">", lt);
	if (gt < 0) throw new Error("pades: /Contents '>' bulunamadı");
	return { start: lt + 1, end: gt };
}

/** CMS DER byte'larını /Contents placeholder'ına hex yazar (uzunluk korunur). */
export function spliceSignature(pdf: Uint8Array, cms: Uint8Array): Uint8Array {
	const { start, end } = findContentsPlaceholder(pdf);
	const placeholderLen = end - start;
	const hex = toHex(cms);
	if (hex.length > placeholderLen) {
		throw new Error(
			`pades: CMS ${cms.length}B hex=${hex.length} > placeholder=${placeholderLen}. signatureSize artır.`,
		);
	}
	const padded = hex + "0".repeat(placeholderLen - hex.length);
	const out = new Uint8Array(pdf);
	for (let i = 0; i < padded.length; i++) out[start + i] = padded.charCodeAt(i);
	return out;
}

function toLatin1(u8: Uint8Array): string {
	// Latin-1 decode: byte → code unit 1-1 eşleşme (PDF ASCII güvenli tarama için).
	let s = "";
	for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
	return s;
}

function toHex(u8: Uint8Array): string {
	let s = "";
	for (let i = 0; i < u8.length; i++) s += u8[i]!.toString(16).padStart(2, "0");
	return s;
}
