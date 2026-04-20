import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { Certificate } from "pkijs";
import * as asn1js from "asn1js";
import { loadPfx } from "../src/pfx.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const pfxExists = (() => {
	try { readFileSync(FIXTURE); return true; } catch { return false; }
})();

test("loadPfx — reference test.p12", { skip: !pfxExists && "run reference/run.sh first" }, async () => {
	const bytes = new Uint8Array(readFileSync(FIXTURE));
	const { privateKey, certificate, chain } = await loadPfx(bytes, "testpass");

	assert.equal(privateKey.algorithm, "RSA");
	assert.ok(privateKey.pkcs8.byteLength > 100, "pkcs8 key too small");
	assert.ok(certificate.byteLength > 100, "cert too small");
	assert.equal(chain.length, 0, "self-signed fixture: no intermediate");

	const asn = asn1js.fromBER(certificate.buffer as ArrayBuffer);
	const cert = new Certificate({ schema: asn.result });
	const cn = cert.subject.typesAndValues
		.find((tv) => tv.type === "2.5.4.3")?.value.valueBlock.value as string | undefined;
	assert.equal(cn, "Test Signer");
});
