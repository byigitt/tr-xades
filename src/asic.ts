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
				manifest?: Uint8Array;
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
		for (let i = 0; i < opts.signatures.length; i++) {
			const s = opts.signatures[i]!;
			const idx = String(i + 1).padStart(3, "0");
			entries[sigName(s.format, idx)] = [s.bytes, { level: 6 }];
			if (s.manifest) entries[`META-INF/ASiCManifest${idx}.xml`] = [s.manifest, { level: 6 }];
		}
	}
	return zipSync(entries);
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
