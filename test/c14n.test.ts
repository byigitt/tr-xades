import { test } from "node:test";
import assert from "node:assert/strict";
import { DOMParser } from "@xmldom/xmldom";
import { canonicalize, c14nAlgFromUri } from "../src/c14n.ts";
import { C14N } from "../src/constants.ts";

function parse(xml: string): Element {
	return new DOMParser().parseFromString(xml, "text/xml").documentElement as unknown as Element;
}

// Known c14n 1.0 vector from W3C TR test suite (simplified subset).
test("c14n10 — attribute ordering + namespace handling", () => {
	const el = parse(`<e2 xmlns:a="urn:a" a:y="1" xmlns="urn:d" x="2"/>`);
	const out = new TextDecoder().decode(canonicalize(el as unknown as Node, "c14n10"));
	// Attributes ordered: ns decls first (xmlns, xmlns:a), then remaining attrs alphabetically.
	assert.equal(out, `<e2 xmlns="urn:d" xmlns:a="urn:a" x="2" a:y="1"></e2>`);
});

test("exc-c14n — drops unused ancestor namespaces", () => {
	const el = parse(`<root xmlns:a="urn:a" xmlns:b="urn:b"><a:inner>x</a:inner></root>`);
	const inner = el.getElementsByTagName("a:inner").item(0)!;
	const out = new TextDecoder().decode(canonicalize(inner as unknown as Node, "exc-c14n"));
	assert.equal(out, `<a:inner xmlns:a="urn:a">x</a:inner>`);
});

test("c14nAlgFromUri round-trip", () => {
	assert.equal(c14nAlgFromUri(C14N["exc-c14n"]), "exc-c14n");
	assert.equal(c14nAlgFromUri(C14N["c14n10"]), "c14n10");
	assert.throws(() => c14nAlgFromUri("http://bogus"), /Unsupported/);
});
