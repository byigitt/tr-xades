// ASiC container (ETSI EN 319 162-1). Zip paketi, paketleme != imzalama —
// kullanıcı önce sign()/cadesSign() ile imzayı üretir, sonra createAsic()
// paketler. read/create tek yerde: S/E, XAdES/CAdES farkı opts'tan.
//
// Zip layout:
//   mimetype                         (STORED, first entry)
//     S: application/vnd.etsi.asic-s+zip
//     E: application/vnd.etsi.asic-e+zip
//   <data>                           (root: ASiC-S tek dosya, ASiC-E çok)
//   META-INF/signatures.xml          (ASiC-S + XAdES)
//   META-INF/signature.p7s           (ASiC-S + CAdES)
//   META-INF/signaturesNNN.xml       (ASiC-E + XAdES)
//   META-INF/signatureNNN.p7s        (ASiC-E + CAdES)
//   META-INF/ASiCManifestNNN.xml     (ASiC-E + CAdES zorunlu; XAdES opsiyonel)

import { strToU8, unzipSync, zipSync } from "fflate";
import { digest } from "./crypto.ts";

export type AsicSignatureFormat = "xades" | "cades";

export type AsicCreateOptions =
	| {
			type: "asic-s";
			data: { name: string; bytes: Uint8Array };
			signature: { bytes: Uint8Array; format: AsicSignatureFormat };
	  }
	| {
			type: "asic-e";
			dataFiles: Array<{ name: string; bytes: Uint8Array }>;
			signatures: Array<{
				bytes: Uint8Array;
				format: AsicSignatureFormat;
				/** Elle verilmiş ASiCManifest XML bytes; `"auto"` verilirse buildAsicManifest
				 *  üretir (tüm dataFiles’ı referanslar). */
				manifest?: Uint8Array | "auto";
			}>;
	  };

export type AsicContents = {
	type: "asic-s" | "asic-e";
	dataFiles: Array<{ name: string; bytes: Uint8Array }>;
	signatures: Array<{ name: string; bytes: Uint8Array; format: AsicSignatureFormat }>;
	manifests: Array<{ name: string; bytes: Uint8Array }>;
};

const MIMETYPE = {
	"asic-s": "application/vnd.etsi.asic-s+zip",
	"asic-e": "application/vnd.etsi.asic-e+zip",
} as const;

type Entry = [Uint8Array, { level: 0 | 6 }];

export function createAsic(opts: AsicCreateOptions): Uint8Array {
	const entries: Record<string, Entry> = {};
	// mimetype: ETSI EN 319 162-1 §A.1 — STORED (level 0), FIRST entry.
	entries.mimetype = [strToU8(MIMETYPE[opts.type]), { level: 0 }];

	if (opts.type === "asic-s") {
		entries[opts.data.name] = [opts.data.bytes, { level: 6 }];
		entries[sigName(opts.signature.format, null)] = [opts.signature.bytes, { level: 6 }];
	} else {
		for (const f of opts.dataFiles) entries[f.name] = [f.bytes, { level: 6 }];
		// Manifest "auto" için dataFiles digest'lerini önceden hesapla (async önce bitir).
		// zipSync senkron olduğu için, auto manifest createAsic'i senkronluktan çıkarır;
		// bu kabul edilir trade-off (MA3'te de I/O’lu).
		for (let i = 0; i < opts.signatures.length; i++) {
			const s = opts.signatures[i]!;
			const idx = String(i + 1).padStart(3, "0");
			entries[sigName(s.format, idx)] = [s.bytes, { level: 6 }];
			if (s.manifest && s.manifest !== "auto") {
				entries[`META-INF/ASiCManifest${idx}.xml`] = [s.manifest, { level: 6 }];
			}
		}
	}
	return zipSync(entries);
}

/**
 * createAsicAsync — manifest:"auto" opsiyonunu destekler (digest hesabı async).
 * Sync `createAsic` auto manifest üretemez; bu helper auto manifest oluşturup
 * ardından sync `createAsic`'i çağırır.
 */
export async function createAsicAsync(opts: AsicCreateOptions): Promise<Uint8Array> {
	if (opts.type === "asic-s") return createAsic(opts);
	// E modu: auto manifest'leri üret
	const resolved = await Promise.all(opts.signatures.map(async (s, i) => {
		const idx = String(i + 1).padStart(3, "0");
		if (s.manifest !== "auto") return s;
		const sigFilename = `META-INF/${s.format === "xades" ? `signatures${idx}.xml` : `signature${idx}.p7s`}`;
		const manifestBytes = await buildAsicManifest({
			sigReference: { uri: sigFilename, mimeType: sigMimeType(s.format) },
			dataFiles: opts.dataFiles,
		});
		return { ...s, manifest: manifestBytes };
	}));
	return createAsic({ ...opts, signatures: resolved });
}

/**
 * EN 319 162-1 §A.4 ASiCManifest XML üretir. Her data dosyası için
 * DataObjectReference + SHA-256 digest (ds:DigestValue) yazılır.
 */
export async function buildAsicManifest(input: {
	sigReference: { uri: string; mimeType: string };
	dataFiles: Array<{ name: string; bytes: Uint8Array }>;
}): Promise<Uint8Array> {
	const refs: string[] = [];
	for (const f of input.dataFiles) {
		const h = await digest("SHA-256", f.bytes);
		const b64 = Buffer.from(h).toString("base64");
		refs.push(
			`  <asic:DataObjectReference URI="${xmlEscape(f.name)}" MimeType="${xmlEscape(mimeTypeFor(f.name))}">\n` +
			`    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>\n` +
			`    <ds:DigestValue>${b64}</ds:DigestValue>\n` +
			`  </asic:DataObjectReference>`,
		);
	}
	const xml = `<?xml version="1.0" encoding="UTF-8"?>\n` +
		`<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n` +
		`  <asic:SigReference URI="${xmlEscape(input.sigReference.uri)}" MimeType="${xmlEscape(input.sigReference.mimeType)}"/>\n` +
		`${refs.join("\n")}\n` +
		`</asic:ASiCManifest>\n`;
	return new TextEncoder().encode(xml);
}

function sigMimeType(format: AsicSignatureFormat): string {
	return format === "cades" ? "application/pkcs7-signature" : "application/x-xades+xml";
}

const MIME_BY_EXT: Record<string, string> = {
	pdf: "application/pdf",
	xml: "application/xml",
	xsl: "application/xml",
	xbrl: "application/xml",
	txt: "text/plain",
	htm: "text/html",
	html: "text/html",
	jpg: "image/jpeg",
	jpeg: "image/jpeg",
	png: "image/png",
	gif: "image/gif",
	zip: "application/zip",
	bin: "application/octet-stream",
	json: "application/json",
};

function mimeTypeFor(name: string): string {
	const ext = name.split(".").pop()?.toLowerCase() ?? "";
	return MIME_BY_EXT[ext] ?? "application/octet-stream";
}

function xmlEscape(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

export function readAsic(bytes: Uint8Array): AsicContents {
	const entries = unzipSync(bytes);
	const mtBytes = entries.mimetype;
	if (!mtBytes) throw new Error("ASiC: mimetype entry yok");
	const mt = new TextDecoder().decode(mtBytes);
	let type: "asic-s" | "asic-e";
	if (mt === MIMETYPE["asic-s"]) type = "asic-s";
	else if (mt === MIMETYPE["asic-e"]) type = "asic-e";
	else throw new Error(`ASiC: bilinmeyen mimetype: ${mt}`);

	const out: AsicContents = { type, dataFiles: [], signatures: [], manifests: [] };
	for (const [name, data] of Object.entries(entries)) {
		if (name === "mimetype") continue;
		if (!name.startsWith("META-INF/")) { out.dataFiles.push({ name, bytes: data }); continue; }
		if (name.includes("ASiCManifest")) { out.manifests.push({ name, bytes: data }); continue; }
		if (/\.p7s$/i.test(name)) out.signatures.push({ name, bytes: data, format: "cades" });
		else if (/\.xml$/i.test(name)) out.signatures.push({ name, bytes: data, format: "xades" });
	}
	return out;
}

function sigName(format: AsicSignatureFormat, idx: string | null): string {
	const ext = format === "xades" ? "xml" : "p7s";
	const base = format === "xades" ? "signatures" : "signature";
	return idx === null ? `META-INF/${base}.${ext}` : `META-INF/${base}${idx}.${ext}`;
}
