import { test } from "node:test";
import assert from "node:assert/strict";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { buildRequest, getTimestamp, parseResponse, verifyTimestamp } from "../src/tsp.ts";
import { digest } from "../src/crypto.ts";

// TR_XADES_LIVE_TSA=1 ile canlı FreeTSA testi. Varsayılan: atlandı
// (ağ bağımlılığı, CI'da yavaş ve güvensiz).
const live = process.env.TR_XADES_LIVE_TSA === "1";

test("buildRequest — DER structure includes digest + nonce", async () => {
	const d = await digest("SHA-256", new TextEncoder().encode("hello"));
	const req = buildRequest({ digest: d, digestAlgorithm: "SHA-256" });
	assert.ok(req.byteLength > 40, "TimeStampReq too small");
	assert.equal(req[0], 0x30, "TimeStampReq must be DER SEQUENCE");
	// digest bytes must appear verbatim inside the request.
	const hex = Buffer.from(req).toString("hex");
	assert.ok(hex.includes(Buffer.from(d).toString("hex")), "digest not embedded");
});

test("parseResponse — rejects malformed bytes", () => {
	assert.throws(() => parseResponse(new Uint8Array([0, 1, 2, 3]), "x"));
});

test("verifyTimestamp — malformed token invalid result döner", async () => {
	const r = await verifyTimestamp(new Uint8Array([0, 1, 2, 3]), { roots: [] });
	assert.equal(r.valid, false);
	assert.equal(r.chain.valid, false);
	assert.match(r.reason ?? "", /ASN\.1|TimeStampToken|ContentInfo/i);
});

test("getTimestamp — FreeTSA round-trip (live)",
	{ skip: !live && "set TR_XADES_LIVE_TSA=1 to run" },
	async () => {
		const data = new TextEncoder().encode(`tr-esign live test ${Date.now()}`);
		const d = await digest("SHA-256", data);
		const ts = await getTimestamp({
			digest: d,
			digestAlgorithm: "SHA-256",
			tsaUrl: "https://freetsa.org/tsr",
		});
		assert.equal(ts.messageImprint.algorithm, "SHA-256");
		assert.deepEqual(ts.messageImprint.value, d);
		const drift = Math.abs(Date.now() - ts.genTime.getTime());
		assert.ok(drift < 5 * 60_000, `genTime drift too large: ${drift}ms`);
	});

test("verifyTimestamp — FreeTSA token embedded root ile valid chain döner (live)",
	{ skip: !live && "set TR_XADES_LIVE_TSA=1 to run" },
	async () => {
		const data = new TextEncoder().encode(`tr-esign verifyTimestamp ${Date.now()}`);
		const d = await digest("SHA-256", data);
		const ts = await getTimestamp({
			digest: d,
			digestAlgorithm: "SHA-256",
			tsaUrl: "https://freetsa.org/tsr",
		});
		const asn = asn1js.fromBER(ts.token.buffer.slice(ts.token.byteOffset, ts.token.byteOffset + ts.token.byteLength));
		const ci = new pkijs.ContentInfo({ schema: asn.result });
		const sd = new pkijs.SignedData({ schema: ci.content });
		const certs = (sd.certificates ?? []).filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate)
			.map((c) => new Uint8Array(c.toSchema().toBER()));
		assert.ok(certs.length >= 2, `expected TSA cert + root, got ${certs.length}`);
		const root = certs[certs.length - 1]!;
		const r = await verifyTimestamp(ts.token, { roots: [root], tsaUrl: "https://freetsa.org/tsr" });
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		assert.equal(r.chain.valid, true, r.chain.valid ? "" : `chain invalid: ${r.chain.reason}`);
		assert.ok(r.signerCertificate && r.signerCertificate.byteLength > 0, "signerCertificate bekleniyor");
		assert.deepEqual(r.messageImprint.value, d);
		assert.equal(r.messageImprint.algorithm, "SHA-256");
	});
