import { test } from "node:test";
import assert from "node:assert/strict";
import { DOMImplementation, DOMParser, XMLSerializer } from "@xmldom/xmldom";
import {
	buildReference,
	buildSignedInfo,
	digestReference,
	type Transform,
} from "../src/references.ts";
import { digest } from "../src/crypto.ts";
import { SIGNED_PROPS_TYPE } from "../src/constants.ts";

test("digestReference — bytes passthrough equals plain digest", async () => {
	const data = new TextEncoder().encode("hello");
	const expected = await digest("SHA-256", data);
	const got = await digestReference(data, [], "SHA-256");
	assert.deepEqual(got, expected);
});

test("digestReference — node-set implicit c14n10 (no transforms)", async () => {
	const doc = new DOMParser().parseFromString(`<a xmlns="urn:t">x</a>`, "text/xml");
	const el = doc.documentElement as unknown as Node;
	const implicit = await digestReference(el, [], "SHA-256");
	// Equivalent to: canonicalize(el, "c14n10") → digest
	const explicit = await digestReference(el, [{ kind: "c14n", alg: "c14n10" }], "SHA-256");
	assert.deepEqual(implicit, explicit);
});

test("digestReference — enveloped-signature strips ds:Signature before c14n", async () => {
	const xml =
		`<root xmlns="urn:t"><data>x</data>` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S1"><ds:foo/></ds:Signature>` +
		`</root>`;
	const doc = new DOMParser().parseFromString(xml, "text/xml");
	const transforms: Transform[] = [
		{ kind: "enveloped-signature", signatureId: "S1" },
		{ kind: "c14n", alg: "exc-c14n" },
	];
	const d1 = await digestReference(doc.documentElement as unknown as Node, transforms, "SHA-256");

	const stripped = new DOMParser().parseFromString(`<root xmlns="urn:t"><data>x</data></root>`, "text/xml");
	const d2 = await digestReference(stripped.documentElement as unknown as Node, [{ kind: "c14n", alg: "exc-c14n" }], "SHA-256");
	assert.deepEqual(d1, d2);
});

test("buildReference — emits expected structure", () => {
	const doc = new DOMImplementation().createDocument(null, null) as unknown as Document;
	const r = buildReference(doc, {
		uri: "#SP-1",
		id: "R1",
		type: SIGNED_PROPS_TYPE,
		digestAlg: "SHA-256",
		digestValue: new Uint8Array(32),
		transforms: [{ kind: "c14n", alg: "exc-c14n" }],
	});
	doc.appendChild(r as unknown as Node);
	const out = new XMLSerializer().serializeToString(r as unknown as Node);
	assert.match(out, /<ds:Reference\b[^>]*Id="R1"/);
	assert.match(out, /URI="#SP-1"/);
	assert.match(out, /Type="http:\/\/uri\.etsi\.org\/01903#SignedProperties"/);
	assert.match(out, /<ds:Transforms>/);
	assert.match(out, /Algorithm="http:\/\/www\.w3\.org\/2001\/10\/xml-exc-c14n#"/);
	assert.match(out, /<ds:DigestMethod\b[^>]*Algorithm="http:\/\/www\.w3\.org\/2001\/04\/xmlenc#sha256"/);
});

test("buildSignedInfo — wraps references + algs", () => {
	const doc = new DOMImplementation().createDocument(null, null) as unknown as Document;
	const r1 = buildReference(doc, { uri: "", digestAlg: "SHA-256", digestValue: new Uint8Array(32) });
	const si = buildSignedInfo(doc, { references: [r1], signatureAlg: "RSA-SHA256", c14nAlg: "exc-c14n" });
	doc.appendChild(si as unknown as Node);
	const out = new XMLSerializer().serializeToString(si as unknown as Node);
	assert.match(out, /<ds:SignedInfo\b/);
	assert.match(out, /<ds:CanonicalizationMethod\b[^>]*Algorithm="http:\/\/www\.w3\.org\/2001\/10\/xml-exc-c14n#"/);
	assert.match(out, /<ds:SignatureMethod\b[^>]*Algorithm="http:\/\/www\.w3\.org\/2001\/04\/xmldsig-more#rsa-sha256"/);
	assert.match(out, /<ds:Reference\b/);
});
