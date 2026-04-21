// PAdES görünür imza (visible signature) — EN 319 142-1 §5.3 + ISO 32000-1 §12.7.5.4.
//
// Bir /Sig dictionary tek başına "görünmez" — PDF Reader üzerine tıklayınca imza
// kontrol penceresi açar. Görünür imza için Widget annotation'a:
//   - nonzero /Rect (sayfa koordinatları)
//   - /AP /N <XObject> (appearance stream: çerçeve + metin + logo)
// atanır. Widget + XObject incremental update olarak PDF'in sonuna eklenir.
//
// Akış: padesSign opts.visibleSignature → addSignaturePlaceholder(widgetRect) →
//       addVisibleAppearance (incremental: new XObject + updated widget) →
//       ByteRange hesapla → imza → splice.
//
// MA3 referans: ma3api-pades-pdfbox VisibleSignature + SignaturePanel
// (page, x, y, width, height, image?, text?). Biz pdf-lib yok, hand-rolled.

export type VisibleSignatureOptions = {
	/** 1-tabanlı sayfa numarası (kullanıcı gözüyle sayfa 1). */
	page: number;
	/** Sayfa koordinatları [x1, y1, x2, y2]. PDF koordinat sistemi: origin sol-alt. */
	rect: [number, number, number, number];
	/** Görünecek çok satırlı metin. Default imzalayan adı + tarih eklenir padesSign'dan. */
	text: string;
	/** PDF standart Helvetica font boyutu (pt). Default 10. */
	fontSize?: number;
};

export type AppearanceResult = {
	/** XObject form içeriği (content stream bytes) */
	content: Uint8Array;
	/** Form XObject /BBox — rect'in genişlik/yüksekliği 0 tabanlı. */
	bbox: [number, number, number, number];
};

/**
 * Metin içerik stream'i üretir. Çerçeve çizgisi + her satırı alt alta yazar.
 * PDF operator'ları: q/Q (state save/restore), BT/ET, Tf (font), Td (position),
 * Tj (show), re/S (rectangle stroke).
 */
export function buildAppearance(opts: VisibleSignatureOptions): AppearanceResult {
	const [x1, y1, x2, y2] = opts.rect;
	const w = Math.abs(x2 - x1);
	const h = Math.abs(y2 - y1);
	const font = opts.fontSize ?? 10;
	const lineHeight = font * 1.25;

	const lines = opts.text.split(/\r?\n/);
	const ops: string[] = [];
	ops.push("q");                                              // save state
	ops.push("0.2 0.2 0.2 RG 0.5 w");                           // stroke color, line width
	ops.push(`0 0 ${w.toFixed(2)} ${h.toFixed(2)} re S`);       // border rectangle
	ops.push("BT");
	ops.push(`/F1 ${font} Tf`);
	// Üstten başla; ilk satır y = h - font * 1.1 (baseline tolerance)
	for (let i = 0; i < lines.length; i++) {
		const y = h - (i + 1) * lineHeight;
		ops.push(`${(4).toFixed(2)} ${y.toFixed(2)} Td`);
		ops.push(`(${pdfString(lines[i]!)}) Tj`);
		// Next Td relative — reset for next iteration
		ops.push(`-${(4).toFixed(2)} -${y.toFixed(2)} Td`);
	}
	ops.push("ET");
	ops.push("Q");
	const stream = ops.join("\n");
	return { content: new TextEncoder().encode(stream), bbox: [0, 0, w, h] };
}

/**
 * /Contents<HEX> placeholder ekli PDF'e visible signature appearance ekler.
 * Widget annotation'ı günceller + yeni XObject + Helvetica Font /Resources eklenir.
 * Incremental update — orijinal ByteRange etkilenmez, yeni bayt eklenir.
 */
export function addVisibleAppearance(pdf: Uint8Array, opts: VisibleSignatureOptions): Uint8Array {
	const str = toLatin1(pdf);

	// Trailer meta
	const lastEof = str.lastIndexOf("%%EOF");
	const sxrIdx = str.lastIndexOf("startxref", lastEof);
	const prevXref = parseInt(str.substring(sxrIdx + 10, lastEof).trim().split(/\s+/)[0]!, 10);
	const trailerIdx = str.lastIndexOf("trailer", lastEof);
	const trailer = str.substring(trailerIdx, sxrIdx);
	const rootM = /\/Root\s+(\d+)\s+\d+\s+R/.exec(trailer);
	const sizeM = /\/Size\s+(\d+)/.exec(trailer);
	if (!rootM || !sizeM) throw new Error("pades-visible: trailer parse hatası");
	let nextObj = parseInt(sizeM[1]!, 10);

	// Widget annotation obj'unu bul — /Subtype/Widget (tek imza alanı varsayıldı).
	const widgetM = /(\d+)\s+0\s+obj\s*<<([^>]*\/Subtype\s*\/Widget[^>]*)>>/s.exec(str);
	if (!widgetM) throw new Error("pades-visible: /Subtype /Widget objesi bulunamadı");
	const widgetNum = parseInt(widgetM[1]!, 10);
	const oldWidgetBody = widgetM[2]!;

	// Page objesi — widget'ı doğru sayfaya bağlamak için /P ref'i.
	// Şimdilik widget'ta /P varsa onu kullan; yoksa addVisiblePages'e bağımlılık yok.
	const pageRef = (/\/P\s+(\d+\s+\d+\s+R)/.exec(oldWidgetBody)?.[1]) ?? null;

	// Appearance content stream
	const app = buildAppearance(opts);

	// Incremental update bytes
	const parts: string[] = [];
	let cursor = pdf.length;

	// Obj 1: Form XObject (appearance)
	const formObjNum = nextObj++;
	const formStr = toLatin1(app.content);
	const formHeader = `\n${formObjNum} 0 obj\n<< /Type /XObject /Subtype /Form ` +
		`/BBox [${app.bbox.join(" ")}] ` +
		`/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> ` +
		`/Length ${app.content.length} >>\nstream\n`;
	const formFooter = "\nendstream\nendobj\n";
	const formFull = formHeader + formStr + formFooter;
	const formOffset = cursor + 1;
	parts.push(formFull);
	cursor += formFull.length;

	// Obj 2: Updated widget (same number) — /Rect + /AP /N formObjNum 0 R
	// Mevcut body'den /Rect ve /AP var mı yoksa ekle; varsa değiştir.
	let newBody = oldWidgetBody;
	const rectStr = `/Rect [${opts.rect.join(" ")}]`;
	newBody = /\/Rect\s*\[[^\]]*\]/.test(newBody)
		? newBody.replace(/\/Rect\s*\[[^\]]*\]/, rectStr)
		: `${newBody} ${rectStr}`;
	const apStr = `/AP << /N ${formObjNum} 0 R >>`;
	newBody = /\/AP\s*<<[^>]*>>/.test(newBody)
		? newBody.replace(/\/AP\s*<<[^>]*>>/, apStr)
		: `${newBody} ${apStr}`;
	const widgetStr = `\n${widgetNum} 0 obj\n<<${newBody}>>\nendobj\n`;
	const widgetOffset = cursor + 1;
	parts.push(widgetStr);
	cursor += widgetStr.length;

	void pageRef; // future: multi-page targeting uses this ref for /P.

	// Yeni xref: sadece güncellenen (widget) + yeni (form) objeler.
	const xrefOffset = cursor;
	const entries: [number, number][] = ([
		[formObjNum, formOffset] as [number, number],
		[widgetNum, widgetOffset] as [number, number],
	]).sort((a, b) => a[0] - b[0]);
	let xref = "xref\n0 1\n0000000000 65535 f \n";
	let i = 0;
	while (i < entries.length) {
		let j = i;
		while (j + 1 < entries.length && entries[j + 1]![0] === entries[j]![0] + 1) j++;
		xref += `${entries[i]![0]} ${j - i + 1}\n`;
		for (let k = i; k <= j; k++) {
			xref += `${entries[k]![1].toString().padStart(10, "0")} 00000 n \n`;
		}
		i = j + 1;
	}
	parts.push(xref);

	const trailerStr = `trailer\n<< /Size ${nextObj} /Root ${rootM[1]} 0 R /Prev ${prevXref} >>\n`;
	parts.push(trailerStr);
	parts.push(`startxref\n${xrefOffset}\n%%EOF\n`);

	const tail = parts.join("");
	const out = new Uint8Array(pdf.length + tail.length);
	out.set(pdf, 0);
	for (let k = 0; k < tail.length; k++) out[pdf.length + k] = tail.charCodeAt(k);
	return out;
}

function pdfString(s: string): string {
	return s.replace(/[\\()]/g, (c) => `\\${c}`);
}

function toLatin1(u8: Uint8Array): string {
	let out = "";
	for (let i = 0; i < u8.length; i++) out += String.fromCharCode(u8[i]!);
	return out;
}
