// PAdES doğrulayıcı. ETSI EN 319 142-1 §5.3.
//
// Akış:
//   1. /ByteRange + /Contents<HEX> alanlarını PDF'ten oku
//   2. ByteRange dilimlerini birleştir → detached content
//   3. /Contents hex'ini DER'e çevir (trailing zero strip)
//   4. `cadesVerify(cms, {detachedContent})` çağır — CMS imza + messageDigest
//      kontrolü CAdES verify ile ortak
//   5. Seviye override: /DSS varsa LT, /SubFilter /ETSI.RFC3161 (DocTimeStamp)
//      varsa LTA. Aksi halde CAdES level (BES/EPES/T).

import { cadesVerify } from "./cades-verify.ts";
import { extractByteRangeBytes, extractCms, readByteRange } from "./pades-core.ts";
import type { VerifyResult } from "./verify.ts";

export async function padesVerify(pdf: Uint8Array): Promise<VerifyResult> {
	let byteRange: [number, number, number, number];
	let cmsDer: Uint8Array;
	try {
		byteRange = readByteRange(pdf);
		cmsDer = extractCms(pdf);
	} catch (e) {
		return { valid: false, reason: `padesVerify: ${(e as Error).message}` };
	}

	const detachedContent = extractByteRangeBytes(pdf, byteRange);
	const r = await cadesVerify(cmsDer, { detachedContent });
	if (!r.valid) return r;

	// PAdES seviye override — DSS (§5.4) ve DocTimeStamp (§5.5) PDF-level yapılar.
	const pdfStr = toLatin1(pdf);
	if (/\/SubFilter\s*\/ETSI\.RFC3161/.test(pdfStr)) r.level = "LTA";
	else if (/\/DSS\s*<</.test(pdfStr)) r.level = "LT";
	return r;
}

function toLatin1(u8: Uint8Array): string {
	let s = "";
	for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
	return s;
}
