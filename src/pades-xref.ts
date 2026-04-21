// PDF trailer / xref helper'ları.
//
// Amaç:
// - classic `trailer << ... >>` PDF'leri parse etmek
// - modern xref-stream (`/Type /XRef`) PDF'lerde trailer bilgisini
//   startxref'in gösterdiği objeden çıkarmak
// - incremental append için sade bir classic xref section yazmak
//
// Tasarım kararı: input xref-stream olsa bile append edilen revision classic
// `xref` + `trailer` + `/Prev <old-startxref>` kullanır. Bu implementasyonu
// küçük tutar; çoğu verifier mixed revision'ları okuyabilir.

export type ParsedTrailer = {
	kind: "classic" | "xref-stream";
	root: string;
	info?: string;
	prev?: number;
	size: number;
	startxref: number;
};

export type XrefEntry = [objNum: number, offset: number];

export function parseTrailer(pdf: Uint8Array): ParsedTrailer {
	const str = toLatin1(pdf);
	const eofIdx = str.lastIndexOf("%%EOF");
	if (eofIdx < 0) throw new Error("pades-xref: %%EOF yok");
	const sxrIdx = str.lastIndexOf("startxref", eofIdx);
	if (sxrIdx < 0) throw new Error("pades-xref: startxref yok");
	const startxref = parseInt(str.substring(sxrIdx + 10, eofIdx).trim().split(/\s+/)[0] ?? "", 10);
	if (!Number.isFinite(startxref)) throw new Error("pades-xref: startxref parse edilemedi");

	const trailerIdx = str.lastIndexOf("trailer", sxrIdx);
	if (trailerIdx >= 0) {
		const dict = readDictionaryAfter(str, trailerIdx + "trailer".length);
		return { kind: "classic", ...parseTrailerDict(dict), startxref };
	}

	const xrefObj = readIndirectObjectAt(str, startxref);
	if (!/\/Type\s*\/XRef\b/.test(xrefObj.dict)) throw new Error("pades-xref: xref stream dictionary bulunamadı");
	return { kind: "xref-stream", ...parseTrailerDict(xrefObj.dict), startxref };
}

export function writeXrefSection(
	entries: XrefEntry[],
	trailer: { size: number; root: string; prev?: number; info?: string; startxref: number },
): string {
	const sorted = [...entries].sort((a, b) => a[0] - b[0]);
	let out = "xref\n0 1\n0000000000 65535 f \n";
	for (let i = 0; i < sorted.length;) {
		let j = i;
		while (j + 1 < sorted.length && sorted[j + 1]![0] === sorted[j]![0] + 1) j++;
		out += `${sorted[i]![0]} ${j - i + 1}\n`;
		for (let k = i; k <= j; k++) out += `${sorted[k]![1].toString().padStart(10, "0")} 00000 n \n`;
		i = j + 1;
	}
	const fields = [`/Size ${trailer.size}`, `/Root ${trailer.root}`];
	if (trailer.info) fields.push(`/Info ${trailer.info}`);
	if (trailer.prev !== undefined) fields.push(`/Prev ${trailer.prev}`);
	out += `trailer\n<< ${fields.join(" ")} >>\n`;
	out += `startxref\n${trailer.startxref}\n%%EOF\n`;
	return out;
}

function parseTrailerDict(dict: string): Omit<ParsedTrailer, "kind" | "startxref"> {
	const root = readRef(dict, "Root");
	const size = readInt(dict, "Size");
	if (!root || size === undefined) throw new Error("pades-xref: /Root veya /Size yok");
	return {
		root,
		...(readRef(dict, "Info") && { info: readRef(dict, "Info") }),
		...(readInt(dict, "Prev") !== undefined && { prev: readInt(dict, "Prev") }),
		size,
	};
}

function readIndirectObjectAt(str: string, offset: number): { objNum: number; gen: number; dict: string } {
	const slice = str.slice(offset);
	const m = /^(\d+)\s+(\d+)\s+obj\b/.exec(slice);
	if (!m) throw new Error(`pades-xref: ${offset} offset'inde indirect object yok`);
	const dict = readDictionaryAfter(slice, m[0].length);
	return { objNum: Number(m[1]), gen: Number(m[2]), dict };
}

function readDictionaryAfter(str: string, offset: number): string {
	const start = str.indexOf("<<", offset);
	if (start < 0) throw new Error("pades-xref: dictionary başlangıcı yok");
	let depth = 0;
	for (let i = start; i < str.length - 1; i++) {
		const pair = str.slice(i, i + 2);
		if (pair === "<<") { depth++; i++; continue; }
		if (pair === ">>") {
			depth--;
			if (depth === 0) return str.slice(start, i + 2);
			i++;
		}
	}
	throw new Error("pades-xref: dictionary kapanışı yok");
}

function readRef(dict: string, key: string): string | undefined {
	return new RegExp(`/${key}\\s+(\\d+\\s+\\d+\\s+R)\\b`).exec(dict)?.[1];
}

function readInt(dict: string, key: string): number | undefined {
	const raw = new RegExp(`/${key}\\s+(\\d+)\\b`).exec(dict)?.[1];
	return raw === undefined ? undefined : Number(raw);
}

function toLatin1(u8: Uint8Array): string {
	let s = "";
	for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
	return s;
}
