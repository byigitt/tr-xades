// XML canonicalization. Thin bridge over xmldsigjs' XmlCanonicalizer, plus the
// algorithm URI → canonicalizer mapping so every caller uses one URI vocabulary.
// Returns UTF-8 bytes (digest-ready). Node may be any W3C DOM Element/Document
// (xmldom's DOM is compatible).

import { XmlCanonicalizer } from "xmldsigjs";
import { C14N } from "./constants.ts";

export type C14NAlg = keyof typeof C14N;

export function canonicalize(node: Node, alg: C14NAlg): Uint8Array {
	// xmldsigjs' XmlCanonicalizer does not emit inherited xmlns declarations on
	// the subset's topmost element when the subtree starts mid-document. That
	// breaks interop with MA3 and any other conformant implementation for
	// inclusive c14n. Workaround: clone the subtree and copy any in-scope xmlns
	// declarations from ancestors onto the clone before canonicalizing. For
	// exclusive c14n the canonicalizer drops unused ones, so it's safe there too.
	const target = node.nodeType === 1 /* ELEMENT_NODE */ ? withInheritedNamespaces(node as Element) : node;
	const c = new XmlCanonicalizer(alg.endsWith("-with-comments"), alg.startsWith("exc-"));
	return new TextEncoder().encode(c.Canonicalize(target));
}

function withInheritedNamespaces(el: Element): Element {
	const clone = el.cloneNode(true) as Element;
	const declared = new Set<string>();
	for (let i = 0; i < clone.attributes.length; i++) {
		const a = clone.attributes.item(i)!;
		if (a.name === "xmlns" || a.name.startsWith("xmlns:")) declared.add(a.name);
	}
	for (let cur: Node | null = el.parentNode; cur && cur.nodeType === 1; cur = cur.parentNode) {
		const attrs = (cur as Element).attributes;
		for (let i = 0; i < attrs.length; i++) {
			const a = attrs.item(i)!;
			if ((a.name === "xmlns" || a.name.startsWith("xmlns:")) && !declared.has(a.name)) {
				clone.setAttribute(a.name, a.value);
				declared.add(a.name);
			}
		}
	}
	return clone;
}

// Resolve URI → alg key; used by verifier when parsing Algorithm= attrs.
export function c14nAlgFromUri(uri: string): C14NAlg {
	for (const k of Object.keys(C14N) as C14NAlg[]) if (C14N[k] === uri) return k;
	throw new Error(`Unsupported canonicalization algorithm: ${uri}`);
}
