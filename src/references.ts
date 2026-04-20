// <ds:Reference> + <ds:SignedInfo> DOM builders and reference-digest computation.
//
// Reference model: a Reference points to data (by URI), optionally applies
// transforms, then digests the result. Supported transforms:
//   - enveloped-signature: strip the ds:Signature matching a given Id from the
//     cloned data before further processing. Used for UBL-TR enveloped.
//   - c14n (any variant): canonicalize node → octet stream.
//   - base64: decode the textContent of the data as base64.
//
// XMLDSig default: if no transform produces an octet stream and data is a node,
// implicit inclusive c14n 1.0 is applied per W3C spec §4.4.3.2.

import { C14N, DIGEST, NS, SIGNATURE, TRANSFORM } from "./constants.ts";
import { canonicalize, type C14NAlg } from "./c14n.ts";
import { digest, type HashAlg, type SignatureAlg } from "./crypto.ts";

export type Transform =
	| { kind: "enveloped-signature"; signatureId?: string }
	| { kind: "c14n"; alg: C14NAlg }
	| { kind: "base64" };

export async function digestReference(
	data: Node | Uint8Array,
	transforms: Transform[],
	digestAlg: HashAlg,
): Promise<Uint8Array> {
	let node: Node | null = data instanceof Uint8Array ? null : data;
	let bytes: Uint8Array | null = data instanceof Uint8Array ? data : null;

	for (const t of transforms) {
		if (t.kind === "enveloped-signature") {
			if (!node) throw new Error("enveloped-signature transform needs node input");
			node = stripSignature(node, t.signatureId);
		} else if (t.kind === "c14n") {
			if (!node) throw new Error("c14n transform needs node input");
			bytes = canonicalize(node, t.alg);
			node = null;
		} else if (t.kind === "base64") {
			const text = node ? (node as Element).textContent ?? "" : new TextDecoder().decode(bytes!);
			bytes = new Uint8Array(Buffer.from(text, "base64"));
			node = null;
		}
	}

	// XMLDSig §4.4.3.2: if final output is a node-set, apply inclusive c14n 1.0.
	if (!bytes && node) bytes = canonicalize(node, "c14n10");
	if (!bytes) throw new Error("digestReference: no octet stream produced");
	return digest(digestAlg, bytes);
}

function stripSignature(node: Node, signatureId?: string): Node {
	const clone = node.cloneNode(true) as Element;
	const sigs = clone.getElementsByTagNameNS(NS.ds, "Signature");
	for (let i = sigs.length - 1; i >= 0; i--) {
		const s = sigs.item(i);
		if (!s) continue;
		if (signatureId && s.getAttribute("Id") !== signatureId) continue;
		s.parentNode?.removeChild(s);
	}
	return clone;
}

export type ReferenceBuildOptions = {
	uri: string;
	id?: string;
	type?: string; // e.g. SIGNED_PROPS_TYPE
	digestAlg: HashAlg;
	digestValue: Uint8Array;
	transforms?: Transform[];
};

export function buildReference(doc: Document, o: ReferenceBuildOptions): Element {
	const r = doc.createElementNS(NS.ds, "ds:Reference");
	if (o.id) r.setAttribute("Id", o.id);
	if (o.type) r.setAttribute("Type", o.type);
	r.setAttribute("URI", o.uri);

	if (o.transforms && o.transforms.length > 0) {
		const ts = doc.createElementNS(NS.ds, "ds:Transforms");
		for (const t of o.transforms) ts.appendChild(buildTransformElement(doc, t));
		r.appendChild(ts);
	}

	const dm = doc.createElementNS(NS.ds, "ds:DigestMethod");
	dm.setAttribute("Algorithm", DIGEST[o.digestAlg]);
	r.appendChild(dm);

	const dv = doc.createElementNS(NS.ds, "ds:DigestValue");
	dv.appendChild(doc.createTextNode(Buffer.from(o.digestValue).toString("base64")));
	r.appendChild(dv);

	return r;
}

function buildTransformElement(doc: Document, t: Transform): Element {
	const el = doc.createElementNS(NS.ds, "ds:Transform");
	if (t.kind === "enveloped-signature") el.setAttribute("Algorithm", TRANSFORM["enveloped-signature"]);
	else if (t.kind === "c14n") el.setAttribute("Algorithm", C14N[t.alg]);
	else if (t.kind === "base64") el.setAttribute("Algorithm", TRANSFORM.base64);
	return el;
}

export type SignedInfoOptions = {
	references: Element[];
	signatureAlg: SignatureAlg;
	c14nAlg: C14NAlg;
	id?: string;
};

export function buildSignedInfo(doc: Document, o: SignedInfoOptions): Element {
	const si = doc.createElementNS(NS.ds, "ds:SignedInfo");
	if (o.id) si.setAttribute("Id", o.id);

	const cm = doc.createElementNS(NS.ds, "ds:CanonicalizationMethod");
	cm.setAttribute("Algorithm", C14N[o.c14nAlg]);
	si.appendChild(cm);

	const sm = doc.createElementNS(NS.ds, "ds:SignatureMethod");
	sm.setAttribute("Algorithm", SIGNATURE[o.signatureAlg]);
	si.appendChild(sm);

	for (const r of o.references) si.appendChild(r);
	return si;
}
