import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRequest, getTimestamp, parseResponse } from "../src/tsp.ts";
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

test("getTimestamp — FreeTSA round-trip (live)",
	{ skip: !live && "set TR_XADES_LIVE_TSA=1 to run" },
	async () => {
		const data = new TextEncoder().encode(`tr-xades live test ${Date.now()}`);
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
