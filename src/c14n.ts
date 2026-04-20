// XML canonicalization. Thin bridge over xmldsigjs' XmlCanonicalizer, plus the
// algorithm URI → canonicalizer mapping so every caller uses one URI vocabulary.
// Returns UTF-8 bytes (digest-ready). Node may be any W3C DOM Element/Document
// (xmldom's DOM is compatible).

import { XmlCanonicalizer } from "xmldsigjs";
import { C14N } from "./constants.ts";

export type C14NAlg = keyof typeof C14N;

export function canonicalize(node: Node, alg: C14NAlg): Uint8Array {
	const c = new XmlCanonicalizer(alg.endsWith("-with-comments"), alg.startsWith("exc-"));
	return new TextEncoder().encode(c.Canonicalize(node));
}

// Resolve URI → alg key; used by verifier when parsing Algorithm= attrs.
export function c14nAlgFromUri(uri: string): C14NAlg {
	for (const k of Object.keys(C14N) as C14NAlg[]) if (C14N[k] === uri) return k;
	throw new Error(`Unsupported canonicalization algorithm: ${uri}`);
}
