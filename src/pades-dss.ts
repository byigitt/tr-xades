// PAdES-LT DSS (Document Security Store) ekleyici. ETSI EN 319 142-1 §5.4.
//
// Mevcut PAdES-B-B PDF'e incremental update olarak eklenir:
//   - Her cert/CRL/OCSP → PDF stream object
//   - /DSS dict → /Certs + /CRLs + /OCSPs dizileri
//   - Güncellenmiş Root object → mevcut alanlar + /DSS ref
//   - Yeni xref section + trailer /Prev eski xref'e işaret eder
//
// Orijinal imza ByteRange'i dokunulmaz; eski bayt-bayt korunur. Incremental
// update kuralı: yalnız yeni bayt eklenir.

import { parseTrailer, writeXrefSection } from "./pades-xref.ts";

export type DssInput = {
	certs?: Uint8Array[];
	crls?: Uint8Array[];
	/** Tam OCSPResponse DER (PAdES spec BasicOCSPResponse DER istese de Adobe/MA3 full kabul ediyor). */
	ocsps?: Uint8Array[];
};

export function addDss(pdf: Uint8Array, dss: DssInput): Uint8Array {
	const str = toLatin1(pdf);
	const trailer = parseTrailer(pdf);
	const rootObjNum = parseInt(trailer.root.split(/\s+/)[0]!, 10);
	let nextObjNum = trailer.size;

	// 2. Mevcut Root object'in BODY'si (son incremental'daki <<..>>).
	// PDF'te "N 0 obj" birden fazla yerde olabilir; scan ederek sonuncuyu al.
	const rootBody = readLatestObjectBody(str, rootObjNum);

	// 3. Append yeni objeler. cursor = dosyanın sonundaki mutlak offset.
	const parts: string[] = [];
	let cursor = pdf.length;

	const streamEntries: { num: number; offset: number; bytes: string }[] = [];
	const appendStream = (der: Uint8Array): number => {
		const num = nextObjNum++;
		const payload = Buffer.from(der).toString("latin1");
		const header = `\n${num} 0 obj\n<< /Length ${der.length} >>\nstream\n`;
		const footer = `\nendstream\nendobj\n`;
		const bytes = header + payload + footer;
		const objOffset = cursor + 1; // leading \n ofset dışı
		streamEntries.push({ num, offset: objOffset, bytes });
		parts.push(bytes);
		cursor += bytes.length;
		return num;
	};

	const certRefs = (dss.certs ?? []).map(appendStream);
	const crlRefs = (dss.crls ?? []).map(appendStream);
	const ocspRefs = (dss.ocsps ?? []).map(appendStream);

	// DSS dict object
	const dssFields = ["/Type /DSS"];
	if (certRefs.length) dssFields.push(`/Certs [${certRefs.map((n) => `${n} 0 R`).join(" ")}]`);
	if (crlRefs.length) dssFields.push(`/CRLs [${crlRefs.map((n) => `${n} 0 R`).join(" ")}]`);
	if (ocspRefs.length) dssFields.push(`/OCSPs [${ocspRefs.map((n) => `${n} 0 R`).join(" ")}]`);
	const dssObjNum = nextObjNum++;
	const dssBytes = `\n${dssObjNum} 0 obj\n<< ${dssFields.join(" ")} >>\nendobj\n`;
	const dssOffset = cursor + 1;
	parts.push(dssBytes);
	cursor += dssBytes.length;

	// Güncellenmiş Root (eski body + /DSS ref)
	const newRootBody = rootBody.includes("/DSS")
		? rootBody.replace(/\/DSS\s+\d+\s+\d+\s+R/, `/DSS ${dssObjNum} 0 R`)
		: `${rootBody.trimEnd()} /DSS ${dssObjNum} 0 R`;
	const rootBytes = `\n${rootObjNum} 0 obj\n<<${newRootBody}>>\nendobj\n`;
	const rootOffset = cursor + 1;
	parts.push(rootBytes);
	cursor += rootBytes.length;

	// 4. Yeni xref section — yalnız güncellenmiş/yeni objeler.
	const entries: [number, number][] = [
		...streamEntries.map(({ num, offset }) => [num, offset] as [number, number]),
		[dssObjNum, dssOffset] as [number, number],
		[rootObjNum, rootOffset] as [number, number],
	];

	const xrefOffset = cursor;
	parts.push(writeXrefSection(entries, {
		size: nextObjNum,
		root: trailer.root,
		...(trailer.info && { info: trailer.info }),
		prev: trailer.startxref,
		startxref: xrefOffset,
	}));

	// 5. Birleştir
	const tail = parts.join("");
	const out = new Uint8Array(pdf.length + tail.length);
	out.set(pdf, 0);
	for (let k = 0; k < tail.length; k++) out[pdf.length + k] = tail.charCodeAt(k);
	return out;
}

function readLatestObjectBody(str: string, objNum: number): string {
	// Son "<objNum> 0 obj\n<<...>>\nendobj" bloğunu bul — incremental update'larda
	// aynı obj numarasının birden fazla versiyonu olabilir.
	const re = new RegExp(`${objNum}\\s+0\\s+obj\\s*<<([\\s\\S]*?)>>\\s*endobj`, "g");
	let last: RegExpExecArray | null = null;
	let m: RegExpExecArray | null;
	while ((m = re.exec(str)) !== null) last = m;
	if (!last) throw new Error(`pades-dss: obj ${objNum} gövdesi bulunamadı`);
	return last[1]!;
}

function toLatin1(u8: Uint8Array): string {
	let s = "";
	for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
	return s;
}
