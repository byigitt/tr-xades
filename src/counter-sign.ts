// XAdES CounterSignature (ETSI TS 101 903 §7.2.4.1).
//
// Mevcut bir ds:Signature'a "karşı imza" atar: yeni bir ds:Signature, parent'ın
// ds:SignatureValue'sunu referans alır ve parent'ın
// xades:UnsignedSignatureProperties/xades:CounterSignature çocuğu olarak yerleştirilir.
// Yeni signature tam bir XAdES-BES (SignedProperties + SigningCertificate dahil).

import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { canonicalize, type C14NAlg } from "./c14n.ts";
import { NS, SIGNED_PROPS_TYPE } from "./constants.ts";
import type { HashAlg, SignatureAlg } from "./crypto.ts";
import { makeId } from "./ids.ts";
import { buildReference, buildSignedInfo, digestReference } from "./references.ts";
import { buildKeyInfo, resolveSigner, type SignerInput } from "./sign.ts";
import { buildSignedProperties, type CommitmentType } from "./signed-properties.ts";
import { ensureUnsignedSignatureProperties } from "./upgrade.ts";

const XMLNS_NS = "http://www.w3.org/2000/xmlns/";
const COUNTERSIGNED_TYPE = "http://uri.etsi.org/01903#CountersignedSignature";

export type CounterSignOptions = {
	xml: string;
	signer: SignerInput;
	// Hangi imzayı karşı-imzalayacağız. Verilmezse belgedeki ilk ds:Signature seçilir.
	parentSignatureId?: string;
	digestAlgorithm?: HashAlg;
	signatureAlgorithm?: SignatureAlg;
	c14nAlgorithm?: C14NAlg;
	signingTime?: Date | null;
	productionPlace?: { city?: string; state?: string; postalCode?: string; country?: string };
	commitmentType?: CommitmentType;
	signerRole?: { claimed: string[] };
};

export async function counterSign(opts: CounterSignOptions): Promise<string> {
	const resolved = await resolveSigner(opts);
	const digestAlg = opts.digestAlgorithm ?? "SHA-256";
	const c14nAlg = opts.c14nAlgorithm ?? "exc-c14n";

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const doc: any = new DOMParser().parseFromString(opts.xml, "text/xml");
	const parentSig = findSignature(doc, opts.parentSignatureId);
	if (!parentSig) throw new Error("counterSign: hedef ds:Signature bulunamadı");

	const parentSV = firstChild(parentSig, NS.ds, "SignatureValue");
	if (!parentSV) throw new Error("counterSign: parent ds:SignatureValue yok");
	let parentSvId = parentSV.getAttribute("Id");
	if (!parentSvId) {
		parentSvId = makeId("Signature-Value");
		parentSV.setAttribute("Id", parentSvId);
	}

	const counterSigId = makeId("Signature");
	const dataRefId = makeId("Reference");

	const sig = doc.createElementNS(NS.ds, "ds:Signature");
	sig.setAttribute("Id", counterSigId);
	sig.setAttributeNS(XMLNS_NS, "xmlns:xades", NS.xades);

	const sp = await buildSignedProperties(doc as Document, {
		certificate: resolved.certificate,
		digestAlgorithm: digestAlg,
		signingTime: opts.signingTime === null ? undefined : (opts.signingTime ?? new Date()),
		productionPlace: opts.productionPlace,
		commitmentType: opts.commitmentType,
		signerRole: opts.signerRole,
		dataObjectFormat: { referenceId: dataRefId, mimeType: "text/xml" },
	});
	const qpObject = doc.createElementNS(NS.ds, "ds:Object");
	qpObject.setAttribute("Id", makeId("Object"));
	const qp = doc.createElementNS(NS.xades, "xades:QualifyingProperties");
	qp.setAttribute("Target", `#${counterSigId}`);
	qp.appendChild(sp.element);
	qpObject.appendChild(qp);

	// Data ref: parent'ın SignatureValue elemanı, c14n → digest.
	const dataDigest = await digestReference(parentSV, [{ kind: "c14n", alg: c14nAlg }], digestAlg);
	const dataRefEl = buildReference(doc as Document, {
		uri: `#${parentSvId}`,
		id: dataRefId,
		type: COUNTERSIGNED_TYPE,
		digestAlg,
		digestValue: dataDigest,
		transforms: [{ kind: "c14n", alg: c14nAlg }],
	});
	const spDigest = await sp.c14nDigest(digestAlg, c14nAlg);
	const spRefEl = buildReference(doc as Document, {
		uri: `#${sp.id}`,
		id: makeId("Reference"),
		type: SIGNED_PROPS_TYPE,
		digestAlg,
		digestValue: spDigest,
		transforms: [{ kind: "c14n", alg: c14nAlg }],
	});

	const si = buildSignedInfo(doc as Document, {
		references: [dataRefEl, spRefEl],
		signatureAlg: resolved.sigAlg,
		c14nAlg,
	});
	// Şema sırası: SignedInfo, SignatureValue, KeyInfo, Object*.
	sig.appendChild(si);

	const sigBytes = await resolved.sign(canonicalize(si, c14nAlg));
	const sv = doc.createElementNS(NS.ds, "ds:SignatureValue");
	sv.setAttribute("Id", makeId("Signature-Value"));
	sv.appendChild(doc.createTextNode(Buffer.from(sigBytes).toString("base64")));
	sig.appendChild(sv);
	sig.appendChild(buildKeyInfo(doc as Document, resolved.certificate));
	sig.appendChild(qpObject);

	// Parent'ın QualifyingProperties'ini bul; UnsignedSignatureProperties garantile; CounterSignature içine yerleştir.
	const parentQp = findDescendant(parentSig, NS.xades, "QualifyingProperties");
	if (!parentQp) throw new Error("counterSign: parent QualifyingProperties yok (XAdES-BES sig gerekli)");
	const usprops = ensureUnsignedSignatureProperties(doc, parentQp);
	const cs = doc.createElementNS(NS.xades, "xades:CounterSignature");
	cs.appendChild(sig);
	usprops.appendChild(cs);

	return new XMLSerializer().serializeToString(doc);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSignature(doc: any, id?: string): any {
	const sigs = doc.getElementsByTagNameNS(NS.ds, "Signature");
	if (!id) return sigs.item(0);
	for (let i = 0; i < sigs.length; i++) {
		const s = sigs.item(i);
		if (s.getAttribute("Id") === id) return s;
	}
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findDescendant(parent: any, ns: string, local: string): any {
	return parent.getElementsByTagNameNS(ns, local).item(0);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function firstChild(parent: any, ns: string, local: string): any {
	for (let n = parent.firstChild; n; n = n.nextSibling) {
		if (n.nodeType === 1 && n.namespaceURI === ns && n.localName === local) return n;
	}
	return null;
}
