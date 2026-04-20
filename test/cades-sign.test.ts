import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { cadesSign } from "../src/cades-sign.ts";
import { CADES_ATTR, CONTENT_TYPE, SIGNED_ATTR } from "../src/cades-constants.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

function parseSignedData(der: Uint8Array): pkijs.SignedData {
	const ab = new ArrayBuffer(der.byteLength);
	new Uint8Array(ab).set(der);
	const ci = new pkijs.ContentInfo({ schema: asn1js.fromBER(ab).result });
	assert.equal(ci.contentType, CONTENT_TYPE.signedData);
	return new pkijs.SignedData({ schema: ci.content });
}

test("cadesSign — attached BES üretir, pkijs parse eder",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const data = new TextEncoder().encode("Hello CAdES");
		const der = await cadesSign({
			data,
			signer: { pfx, password: "testpass" },
			signingTime: new Date("2026-04-20T10:00:00Z"),
		});

		assert.ok(der.byteLength > 500, "minimum CAdES size check");
		const sd = parseSignedData(der);

		// encapContentInfo: data OID + eContent (attached)
		assert.equal(sd.encapContentInfo.eContentType, CONTENT_TYPE.data);
		assert.ok(sd.encapContentInfo.eContent, "attached: eContent olmalı");

		// Bir signerInfo
		assert.equal(sd.signerInfos.length, 1);
		const si = sd.signerInfos[0]!;
		const attrs = si.signedAttrs?.attributes ?? [];

		// Zorunlu: contentType + messageDigest + signingCertificateV2 + signingTime
		const types = attrs.map((a) => a.type);
		assert.ok(types.includes(SIGNED_ATTR.contentType));
		assert.ok(types.includes(SIGNED_ATTR.messageDigest));
		assert.ok(types.includes(SIGNED_ATTR.signingTime));
		assert.ok(types.includes(CADES_ATTR.signingCertificateV2));

		// Sertifika set'te
		assert.ok(sd.certificates && sd.certificates.length >= 1);

		// Signature bytes doldurulmuş
		assert.ok(si.signature.valueBlock.valueHexView.byteLength > 0);
	});

test("cadesSign — detached mode (contentIncluded=false): eContent yok",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const data = new TextEncoder().encode("detached");
		const der = await cadesSign({
			data,
			signer: { pfx, password: "testpass" },
			contentIncluded: false,
			signingTime: null,
		});
		const sd = parseSignedData(der);
		assert.ok(!sd.encapContentInfo.eContent, "detached: eContent olmamalı");
		// signingTime=null → attribute eklenmez
		const types = (sd.signerInfos[0]!.signedAttrs?.attributes ?? []).map((a) => a.type);
		assert.ok(!types.includes(SIGNED_ATTR.signingTime));
	});
