import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { cadesSign } from "../src/cades-sign.ts";
import { cadesCounterSign } from "../src/cades-counter-sign.ts";
import { cadesVerify } from "../src/cades-verify.ts";
import { CONTENT_TYPE, SIGNED_ATTR } from "../src/cades-constants.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("cadesCounterSign — unsignedAttrs'a id-countersignature ekler",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signer = { pfx, password: "testpass" };
		const bes = await cadesSign({ data: new TextEncoder().encode("orig"), signer });
		const cs = await cadesCounterSign({ cms: bes, signer });

		// Parse + assert countersignature attribute present
		const ab = new ArrayBuffer(cs.byteLength);
		new Uint8Array(ab).set(cs);
		const ci = new pkijs.ContentInfo({ schema: asn1js.fromBER(ab).result });
		assert.equal(ci.contentType, CONTENT_TYPE.signedData);
		const sd = new pkijs.SignedData({ schema: ci.content });
		const outer = sd.signerInfos[0]!;
		const unsigned = outer.unsignedAttrs?.attributes ?? [];
		const cAttrs = unsigned.filter((a) => a.type === SIGNED_ATTR.countersignature);
		assert.equal(cAttrs.length, 1, "tek counter-sig beklenir");

		// Counter SignerInfo'nun signedAttrs içinde contentType OLMAMALI (RFC 5126 §4)
		const counterSchema = cAttrs[0]!.values[0];
		const counterSi = new pkijs.SignerInfo({ schema: counterSchema });
		const csSignedTypes = new Set((counterSi.signedAttrs?.attributes ?? []).map((a) => a.type));
		assert.equal(csSignedTypes.has(SIGNED_ATTR.contentType), false, "contentType olmamalı");
		assert.equal(csSignedTypes.has(SIGNED_ATTR.messageDigest), true, "messageDigest zorunlu");
	});

test("cadesCounterSign → cadesVerify counterSignatures[] raporu",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signer = { pfx, password: "testpass" };
		const bes = await cadesSign({ data: new TextEncoder().encode("hello"), signer });
		const cs = await cadesCounterSign({ cms: bes, signer });
		const r = await cadesVerify(cs);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES", "outer imza BES kalır");
		assert.equal(r.counterSignatures?.length, 1);
		assert.match(r.counterSignatures![0]!.subject, /CN=Test Signer/);
	});

test("cadesCounterSign — iki counter-signer art arda eklenebilir",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const signer = { pfx, password: "testpass" };
		const bes = await cadesSign({ data: new TextEncoder().encode("multi"), signer });
		const cs1 = await cadesCounterSign({ cms: bes, signer });
		const cs2 = await cadesCounterSign({ cms: cs1, signer });
		const r = await cadesVerify(cs2);
		assert.equal(r.valid, true);
		if (!r.valid) return;
		assert.equal(r.counterSignatures?.length, 2);
	});

test("cadesCounterSign — bozuk CMS reddi", async () => {
	await assert.rejects(() => cadesCounterSign({
		cms: new Uint8Array([0, 1, 2, 3]),
		signer: { pfx: new Uint8Array(), password: "" },
	}));
});
