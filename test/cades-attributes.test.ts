import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as asn1js from "asn1js";
import {
	buildContentTypeAttr,
	buildMessageDigestAttr,
	buildSigningCertificateV2Attr,
	buildSigningTimeAttr,
} from "../src/cades-attributes.ts";
import { CADES_ATTR, CONTENT_TYPE, SIGNED_ATTR } from "../src/cades-constants.ts";
import { loadPfx } from "../src/pfx.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("buildContentTypeAttr — data OID (default)", () => {
	const a = buildContentTypeAttr();
	assert.equal(a.type, SIGNED_ATTR.contentType);
	assert.equal(a.values.length, 1);
	assert.ok(a.values[0] instanceof asn1js.ObjectIdentifier);
	assert.equal((a.values[0] as asn1js.ObjectIdentifier).valueBlock.toString(), CONTENT_TYPE.data);
});

test("buildMessageDigestAttr — OCTET STRING value", () => {
	const digest = new Uint8Array(32).fill(0x42);
	const a = buildMessageDigestAttr(digest);
	assert.equal(a.type, SIGNED_ATTR.messageDigest);
	assert.ok(a.values[0] instanceof asn1js.OctetString);
	const bytes = new Uint8Array((a.values[0] as asn1js.OctetString).valueBlock.valueHexView);
	assert.deepEqual(bytes, digest);
});

test("buildSigningTimeAttr — 2026 → UTCTime", () => {
	const a = buildSigningTimeAttr(new Date("2026-04-20T10:00:00Z"));
	assert.ok(a.values[0] instanceof asn1js.UTCTime);
});

test("buildSigningTimeAttr — 2050 → GeneralizedTime", () => {
	const a = buildSigningTimeAttr(new Date("2050-01-01T00:00:00Z"));
	assert.ok(a.values[0] instanceof asn1js.GeneralizedTime);
});

test("buildSigningCertificateV2Attr — SHA-256 default, certHash + issuerSerial",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const b = await loadPfx(new Uint8Array(readFileSync(FIXTURE)), "testpass");
		const a = await buildSigningCertificateV2Attr(b.certificate);
		assert.equal(a.type, CADES_ATTR.signingCertificateV2);
		// SigningCertificateV2 ::= SEQ { SEQ OF ESSCertIDv2 }
		const sigCertV2 = a.values[0] as asn1js.Sequence;
		assert.equal(sigCertV2.valueBlock.value.length, 1);
		const certs = sigCertV2.valueBlock.value[0] as asn1js.Sequence;
		assert.equal(certs.valueBlock.value.length, 1); // tek ESSCertIDv2
		const essCert = certs.valueBlock.value[0] as asn1js.Sequence;
		// SHA-256 DEFAULT → alg atlanır; 2 child var: certHash + issuerSerial
		assert.equal(essCert.valueBlock.value.length, 2);
		assert.ok(essCert.valueBlock.value[0] instanceof asn1js.OctetString);
		// issuerSerial sequence — issuer GeneralNames + serialNumber
		const issuerSerial = essCert.valueBlock.value[1] as asn1js.Sequence;
		assert.equal(issuerSerial.valueBlock.value.length, 2);
	});

test("buildSigningCertificateV2Attr — SHA-384 emits hashAlgorithm",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const b = await loadPfx(new Uint8Array(readFileSync(FIXTURE)), "testpass");
		const a = await buildSigningCertificateV2Attr(b.certificate, "SHA-384");
		const sigCertV2 = a.values[0] as asn1js.Sequence;
		const certs = sigCertV2.valueBlock.value[0] as asn1js.Sequence;
		const essCert = certs.valueBlock.value[0] as asn1js.Sequence;
		// Non-default hash → 3 child: alg + certHash + issuerSerial
		assert.equal(essCert.valueBlock.value.length, 3);
	});
