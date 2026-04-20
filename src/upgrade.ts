// XAdES seviye yükseltici. BES/EPES → T → LT → LTA.
//
// Tek `upgrade()` fonksiyonu, to parametresine göre davranış:
//   to:"T"   → SignatureTimeStamp ekle (ETSI TS 101 903 §7.3)
//   to:"LT"  → CertificateValues + RevocationValues ekle (§ XAdES-X-L pattern)
//   to:"LTA" → ArchiveTimeStamp ekle (§A.1.5.2 / EN 319 132 §5.5.2)
// Level cascading yok — kullanıcı hedeflediği seviyeye göre sırayla çağırır
// (BES→T→LT→LTA). Her upgrade tek iş.

import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { canonicalize, c14nAlgFromUri, type C14NAlg } from "./c14n.ts";
import { C14N, NS } from "./constants.ts";
import { digest, type HashAlg } from "./crypto.ts";
import { makeId } from "./ids.ts";
import { getTimestamp } from "./tsp.ts";

export type UpgradeOptions =
	| { xml: string; to: "T"; tsa?: { url?: string; policyOid?: string }; digestAlgorithm?: HashAlg; c14nAlgorithm?: C14NAlg }
	| { xml: string; to: "LT"; chain: Uint8Array[]; crls?: Uint8Array[]; ocsps?: Uint8Array[] }
	| { xml: string; to: "LTA"; tsa?: { url?: string; policyOid?: string }; digestAlgorithm?: HashAlg; c14nAlgorithm?: C14NAlg };

export async function upgrade(opts: UpgradeOptions): Promise<string> {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const doc: any = new DOMParser().parseFromString(opts.xml, "text/xml");
	const sig = first(doc, NS.ds, "Signature");
	if (!sig) throw new Error("ds:Signature bulunamadı");
	const qp = first(sig, NS.xades, "QualifyingProperties");
	if (!qp) throw new Error("xades:QualifyingProperties bulunamadı");
	const usprops = ensureUnsignedSignatureProperties(doc, qp);

	if (opts.to === "T") await addSignatureTimeStamp(doc, sig, usprops, opts);
	else if (opts.to === "LT") addLongTermValues(doc, usprops, opts);
	else if (opts.to === "LTA") await addArchiveTimeStamp(doc, sig, usprops, opts);

	return new XMLSerializer().serializeToString(doc);
}

// ---- XAdES-T ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function addSignatureTimeStamp(doc: any, sig: any, usprops: any, o: Extract<UpgradeOptions, { to: "T" }>): Promise<void> {
	const sv = firstChild(sig, NS.ds, "SignatureValue");
	if (!sv) throw new Error("ds:SignatureValue bulunamadı");
	const c14nAlg = o.c14nAlgorithm ?? detectC14n(sig);
	const hashAlg = o.digestAlgorithm ?? "SHA-256";

	const d = await digest(hashAlg, canonicalize(sv, c14nAlg));
	const ts = await getTimestamp({
		digest: d,
		digestAlgorithm: hashAlg,
		tsaUrl: o.tsa?.url,
		policyOid: o.tsa?.policyOid,
	});

	const st = doc.createElementNS(NS.xades, "xades:SignatureTimeStamp");
	st.setAttribute("Id", makeId("Signature-TimeStamp"));
	const cm = doc.createElementNS(NS.ds, "ds:CanonicalizationMethod");
	cm.setAttribute("Algorithm", C14N[c14nAlg]);
	st.appendChild(cm);
	const ets = doc.createElementNS(NS.xades, "xades:EncapsulatedTimeStamp");
	ets.appendChild(doc.createTextNode(Buffer.from(ts.token).toString("base64")));
	st.appendChild(ets);
	usprops.appendChild(st);
}

// ---- XAdES-LT ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function addLongTermValues(doc: any, usprops: any, o: Extract<UpgradeOptions, { to: "LT" }>): void {
	const cv = doc.createElementNS(NS.xades, "xades:CertificateValues");
	cv.setAttribute("Id", makeId("Certificate-Values"));
	for (const d of o.chain) cv.appendChild(encap(doc, "xades:EncapsulatedX509Certificate", d));
	usprops.appendChild(cv);

	const crls = o.crls ?? [];
	const ocsps = o.ocsps ?? [];
	if (crls.length === 0 && ocsps.length === 0) return;

	const rv = doc.createElementNS(NS.xades, "xades:RevocationValues");
	rv.setAttribute("Id", makeId("Revocation-Values"));
	if (crls.length) {
		const group = doc.createElementNS(NS.xades, "xades:CRLValues");
		for (const d of crls) group.appendChild(encap(doc, "xades:EncapsulatedCRLValue", d));
		rv.appendChild(group);
	}
	if (ocsps.length) {
		const group = doc.createElementNS(NS.xades, "xades:OCSPValues");
		for (const d of ocsps) group.appendChild(encap(doc, "xades:EncapsulatedOCSPValue", d));
		rv.appendChild(group);
	}
	usprops.appendChild(rv);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function encap(doc: any, qname: string, der: Uint8Array): any {
	const e = doc.createElementNS(NS.xades, qname);
	e.appendChild(doc.createTextNode(Buffer.from(der).toString("base64")));
	return e;
}

// ---- XAdES-LTA ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function addArchiveTimeStamp(doc: any, sig: any, usprops: any, o: Extract<UpgradeOptions, { to: "LTA" }>): Promise<void> {
	const c14nAlg = o.c14nAlgorithm ?? detectC14n(sig);
	const hashAlg = o.digestAlgorithm ?? "SHA-256";

	// ETSI TS 101 903 §A.1.5.2: ArchiveTimeStamp'ın TSToken message imprint'i,
	// aşağıdakilerin canonicalize edilmiş byte'larının sıralı concatenation'ı:
	//   1. Her ds:Reference'ın referanslandığı data (in-doc Object'ler bu sınıfa girer)
	//   2. ds:SignedInfo
	//   3. ds:SignatureValue
	//   4. ds:KeyInfo (varsa)
	//   5. xades:UnsignedSignatureProperties çocukları (önceki ArchiveTimeStamp'lar HİÇ).
	const parts: Uint8Array[] = [];

	// 1 + 4: Objects (data objects + QualifyingProperties wrapper). ds:Object
	// directly under ds:Signature kapsar hem veriyi hem QualifyingProperties'i.
	for (const obj of childrenByTag(sig, NS.ds, "Object")) parts.push(canonicalize(obj, c14nAlg));

	const si = firstChild(sig, NS.ds, "SignedInfo");
	if (!si) throw new Error("ds:SignedInfo bulunamadı");
	parts.push(canonicalize(si, c14nAlg));

	const sv = firstChild(sig, NS.ds, "SignatureValue");
	if (!sv) throw new Error("ds:SignatureValue bulunamadı");
	parts.push(canonicalize(sv, c14nAlg));

	const ki = firstChild(sig, NS.ds, "KeyInfo");
	if (ki) parts.push(canonicalize(ki, c14nAlg));

	for (let n = usprops.firstChild; n; n = n.nextSibling) {
		if (n.nodeType !== 1) continue;
		// Onceki ArchiveTimeStamp'lar DİŞLANIR (xades 1.3.2 ve xades141 her ikisi).
		if (n.localName === "ArchiveTimeStamp") continue;
		parts.push(canonicalize(n, c14nAlg));
	}

	const total = new Uint8Array(parts.reduce((s, p) => s + p.byteLength, 0));
	let off = 0;
	for (const p of parts) { total.set(p, off); off += p.byteLength; }

	const d = await digest(hashAlg, total);
	const ts = await getTimestamp({
		digest: d,
		digestAlgorithm: hashAlg,
		tsaUrl: o.tsa?.url,
		policyOid: o.tsa?.policyOid,
	});

	const at = doc.createElementNS(NS.xades, "xades:ArchiveTimeStamp");
	at.setAttribute("Id", makeId("Archive-TimeStamp"));
	const cm = doc.createElementNS(NS.ds, "ds:CanonicalizationMethod");
	cm.setAttribute("Algorithm", C14N[c14nAlg]);
	at.appendChild(cm);
	const ets = doc.createElementNS(NS.xades, "xades:EncapsulatedTimeStamp");
	ets.appendChild(doc.createTextNode(Buffer.from(ts.token).toString("base64")));
	at.appendChild(ets);
	usprops.appendChild(at);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function childrenByTag(parent: any, ns: string, local: string): any[] {
	const out: unknown[] = [];
	for (let n = parent.firstChild; n; n = n.nextSibling) {
		if (n.nodeType === 1 && n.namespaceURI === ns && n.localName === local) out.push(n);
	}
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return out as any[];
}

// ---- shared helpers ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function ensureUnsignedSignatureProperties(doc: any, qp: any): any {
	let uprops = firstChild(qp, NS.xades, "UnsignedProperties");
	if (!uprops) {
		uprops = doc.createElementNS(NS.xades, "xades:UnsignedProperties");
		qp.appendChild(uprops);
	}
	let usprops = firstChild(uprops, NS.xades, "UnsignedSignatureProperties");
	if (!usprops) {
		usprops = doc.createElementNS(NS.xades, "xades:UnsignedSignatureProperties");
		uprops.appendChild(usprops);
	}
	return usprops;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function detectC14n(sig: any): C14NAlg {
	const si = first(sig, NS.ds, "SignedInfo");
	const cm = si ? firstChild(si, NS.ds, "CanonicalizationMethod") : null;
	const uri = cm?.getAttribute("Algorithm");
	if (!uri) throw new Error("SignedInfo'da CanonicalizationMethod bulunamadı");
	return c14nAlgFromUri(uri);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function first(parent: any, ns: string, local: string): any {
	return parent.getElementsByTagNameNS(ns, local).item(0);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function firstChild(parent: any, ns: string, local: string): any {
	for (let n = parent.firstChild; n; n = n.nextSibling) {
		if (n.nodeType === 1 && n.namespaceURI === ns && n.localName === local) return n;
	}
	return null;
}
