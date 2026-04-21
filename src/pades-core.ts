// PAdES primitives — PDF incremental update placeholder + ByteRange + splice.
// ETSI EN 319 142-1 §5.3: /SubFilter /ETSI.CAdES.detached, CMS SignedData
// detached, eContent yok; messageDigest = hash(ByteRange bytes).
//
// Placeholder ekleme @signpdf/placeholder-plain ile.
// Ancak bu paket classic xref table bekliyor. Modern xref-stream PDF gelirse
// önce clean-room normalize ediyoruz: ObjStm içindeki sıkıştırılmış objeleri
// dosya sonuna açıp standalone yazıyor, ardından full classic xref table
// append ediyoruz. Böylece signpdf sadece classic son revision'ı görüyor.
// ByteRange ve /Contents scanning yine elimizde.

import { inflateSync } from "node:zlib";
import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SUBFILTER_ETSI_CADES_DETACHED } from "@signpdf/utils";
import { parseTrailer, writeXrefSection } from "./pades-xref.ts";

/** DocTimeStamp SubFilter — EN 319 142-1 §5.5. */
export const SUBFILTER_ETSI_RFC3161 = "ETSI.RFC3161";

export type PlaceholderOptions = {
	reason?: string;
	location?: string;
	contactInfo?: string;
	signerName?: string;
	/** /Contents placeholder boyutu (bayt). 16384 çoğu CMS'e yeter. */
	signatureSize?: number;
	/** PDF /SubFilter alanı. Default PAdES-B-B için ETSI.CAdES.detached;
	 *  PAdES-LTA DocTimeStamp için ETSI.RFC3161. */
	subFilter?: string;
};

export function addSignaturePlaceholder(pdfIn: Uint8Array, opts: PlaceholderOptions = {}): Uint8Array {
	const pdf = normalizeForPlaceholder(pdfIn);
	const raw = plainAddPlaceholder({
		pdfBuffer: Buffer.from(pdf),
		reason: opts.reason ?? "Signing",
		location: opts.location ?? "",
		contactInfo: opts.contactInfo ?? "",
		name: opts.signerName ?? "",
		signatureLength: opts.signatureSize ?? 16384,
		subFilter: opts.subFilter ?? SUBFILTER_ETSI_CADES_DETACHED,
	});
	// @signpdf /ByteRange için placeholder yazıyor ([0 /********** ...]);
	// asıl değerleri /Contents pozisyonundan hesaplayıp aynı genişlikle yaz.
	return writeByteRange(new Uint8Array(raw));
}

function writeByteRange(pdf: Uint8Array): Uint8Array {
	const str = toLatin1(pdf);
	// Birden çok imza varsa son (yeni eklenmiş) placeholder'ı bul (içinde
	// '/**********' deseni var). Diğerleri zaten actual değerlerle yazılmış.
	const re = /\/ByteRange\s*\[[^\]]*\]/g;
	let brMatch: RegExpExecArray | null = null;
	let m: RegExpExecArray | null;
	while ((m = re.exec(str)) !== null) {
		if (m[0].includes("*")) { brMatch = m; break; }
	}
	if (!brMatch) throw new Error("pades: /ByteRange placeholder (/**********) bulunamadı");
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
	// Birden fazla imza varsa son (en yeni) /ByteRange'ı al — findContentsPlaceholder
	// ile tutarlı olsun diye; doğrulama yeni imzayı hedefler.
	const re = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/g;
	let last: RegExpExecArray | null = null;
	let m: RegExpExecArray | null;
	while ((m = re.exec(str)) !== null) last = m;
	if (!last) throw new Error("pades: /ByteRange bulunamadı");
	return [Number(last[1]), Number(last[2]), Number(last[3]), Number(last[4])];
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

/**
 * /Contents<HEX> bölgesinin hex içerik sınırları (exclusive <, >).
 * PDF'te birden çok /Contents olabilir (page content stream `/Contents N 0 R`
 * + signature hex string); biz hex-string olanların **sonuncusunu** ararız.
 */
export function findContentsPlaceholder(pdf: Uint8Array): { start: number; end: number } {
	const str = toLatin1(pdf);
	const re = /\/Contents\s*<([0-9a-fA-F\s]*)>/g;
	let last: RegExpExecArray | null = null;
	let m: RegExpExecArray | null;
	while ((m = re.exec(str)) !== null) last = m;
	if (!last) throw new Error("pades: /Contents<HEX> placeholder bulunamadı");
	const fullStart = last.index;
	const lt = str.indexOf("<", fullStart);
	const gt = str.indexOf(">", lt);
	return { start: lt + 1, end: gt };
}

/** /Contents hex'inden CMS DER'i çıkarır (trailing zero strip). Boşsa hata. */
export function extractCms(pdf: Uint8Array): Uint8Array {
	const { start, end } = findContentsPlaceholder(pdf);
	const hex = toLatin1(pdf.subarray(start, end)).replace(/\s/g, "").replace(/0+$/, "");
	if (hex.length === 0) throw new Error("pades: /Contents hex boş — PDF imzalanmamış");
	const even = hex + (hex.length % 2 ? "0" : "");
	return new Uint8Array(Buffer.from(even, "hex"));
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

function normalizeForPlaceholder(pdf: Uint8Array): Uint8Array {
	const trailer = parseTrailer(pdf);
	if (trailer.kind === "classic") return pdf;

	const str = toLatin1(pdf);
	const offsets = new Map<number, number>();
	for (const m of str.matchAll(/(\d+)\s+(\d+)\s+obj\b/g)) offsets.set(Number(m[1]), m.index!);

	const parts: string[] = [];
	let cursor = pdf.length;
	for (const obj of readObjectStreams(str)) {
		for (const entry of expandObjectStream(obj)) {
			const bytes = `\n${entry.num} 0 obj\n${entry.body}\nendobj\n`;
			const offset = cursor + 1;
			offsets.set(entry.num, offset);
			parts.push(bytes);
			cursor += bytes.length;
		}
	}

	const xrefOffset = cursor;
	parts.push(writeXrefSection([...offsets.entries()], {
		size: trailer.size,
		root: trailer.root,
		...(trailer.info && { info: trailer.info }),
		startxref: xrefOffset,
	}));

	const tail = parts.join("");
	const out = new Uint8Array(pdf.length + tail.length);
	out.set(pdf, 0);
	for (let i = 0; i < tail.length; i++) out[pdf.length + i] = tail.charCodeAt(i);
	return out;
}

function readObjectStreams(str: string): { dict: string; stream: Uint8Array }[] {
	const out: { dict: string; stream: Uint8Array }[] = [];
	const re = /(\d+)\s+(\d+)\s+obj\s*<<(.*?)>>\s*stream\r?\n/gs;
	let m: RegExpExecArray | null;
	while ((m = re.exec(str)) !== null) {
		if (!/\/Type\s*\/ObjStm\b/.test(m[3]!)) continue;
		const length = /\/Length\s+(\d+)\b/.exec(m[3]!)?.[1];
		if (!length) throw new Error("pades: ObjStm /Length yok");
		const start = m.index + m[0].length;
		const end = start + Number(length);
		out.push({ dict: m[3]!, stream: new Uint8Array(Buffer.from(str.slice(start, end), "latin1")) });
		re.lastIndex = end;
	}
	return out;
}

function expandObjectStream(obj: { dict: string; stream: Uint8Array }): Array<{ num: number; body: string }> {
	const n = Number(/\/N\s+(\d+)\b/.exec(obj.dict)?.[1]);
	const first = Number(/\/First\s+(\d+)\b/.exec(obj.dict)?.[1]);
	if (!Number.isFinite(n) || !Number.isFinite(first)) throw new Error("pades: ObjStm /N veya /First yok");
	const plain = inflateSync(Buffer.from(obj.stream)).toString("latin1");
	const head = plain.slice(0, first).trim();
	const body = plain.slice(first);
	const nums = head.split(/\s+/).map((s) => Number(s));
	if (nums.length !== n * 2) throw new Error("pades: ObjStm index parse hatası");
	const out: Array<{ num: number; body: string }> = [];
	for (let i = 0; i < nums.length; i += 2) {
		const num = nums[i]!;
		const start = nums[i + 1]!;
		const end = i + 3 < nums.length ? nums[i + 3]! : body.length;
		out.push({ num, body: body.slice(start, end).trim() });
	}
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
