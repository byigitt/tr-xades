import { test } from "node:test";
import assert from "node:assert/strict";
import { trPolicy } from "../src/policy.ts";

test("trPolicy — TR profile OIDs match runtime-extracted MA3 values", () => {
	assert.equal(trPolicy("P2").oid, "2.16.792.1.61.0.1.5070.3.1.1");
	assert.equal(trPolicy("P3").oid, "2.16.792.1.61.0.1.5070.3.2.1");
	assert.equal(trPolicy("P4").oid, "2.16.792.1.61.0.1.5070.3.3.1");
});

test("trPolicy — digest is a 32-byte SHA-256 value", () => {
	const p = trPolicy("P3");
	assert.equal(p.digestAlgorithm, "SHA-256");
	assert.equal(p.digest.byteLength, 32);
	assert.equal(
		Buffer.from(p.digest).toString("hex"),
		"ff39bd29463383f69b2052ac47439e06ce7c3b8646e888b6e5ae3e46ba08117a",
	);
});
