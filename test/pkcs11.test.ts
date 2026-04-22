// PKCS#11 testleri — opt-in (SoftHSM2 veya gerçek akıllı kart modülü lazım).
//
// Çalıştırmak için:
//   brew install softhsm
//   export SOFTHSM2_CONF=/tmp/softhsm2.conf
//   softhsm2-util --init-token --slot 0 --label test --so-pin 1234 --pin 1234
//   # test.p12 içeriğini token'a import et:
//   openssl pkcs12 -in reference/fixtures/test.p12 -passin pass:testpass \
//       -nocerts -nodes | openssl pkcs8 -topk8 -nocrypt -outform DER -out /tmp/k.der
//   openssl pkcs12 -in reference/fixtures/test.p12 -passin pass:testpass \
//       -clcerts -nokeys | openssl x509 -outform DER -out /tmp/c.der
//   pkcs11-tool --module /opt/homebrew/lib/softhsm/libsofthsm2.so --login --pin 1234 \
//       --write-object /tmp/k.der --type privkey --label trEsignSigner --id 01
//   pkcs11-tool --module /opt/homebrew/lib/softhsm/libsofthsm2.so --login --pin 1234 \
//       --write-object /tmp/c.der --type cert --label trEsignSigner --id 01
//   TR_ESIGN_PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
//       TR_ESIGN_PKCS11_PIN=1234 pnpm test

import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { cadesSign } from "../src/cades-sign.ts";
import { cadesVerify } from "../src/cades-verify.ts";
import { padesSign } from "../src/pades-sign.ts";
import { padesVerify } from "../src/pades-verify.ts";
import { openPkcs11 } from "../src/pkcs11.ts";
import { sign } from "../src/sign.ts";
import { verify } from "../src/verify.ts";

const MODULE = process.env.TR_ESIGN_PKCS11_MODULE;
const PIN = process.env.TR_ESIGN_PKCS11_PIN ?? "1234";
const LABEL = process.env.TR_ESIGN_PKCS11_LABEL ?? "trEsignSigner";
const enabled = Boolean(MODULE);
const skipMsg = "needs TR_ESIGN_PKCS11_MODULE=/path/to/lib.so (+ PIN + LABEL)";
const PFX_FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const SIGN_PATH = join(import.meta.dirname, "..", "src", "sign.ts");

test("pkcs11 optional — pfx sign yolu graphene-pk11 çözmeden çalışır", async () => {
	const script = `
		import Module from "node:module";
		import { readFileSync } from "node:fs";
		const originalLoad = Module._load;
		Module._load = function(request, parent, isMain) {
			if (request === "graphene-pk11" || request === "pkcs11js") {
				throw new Error("blocked optional pkcs11 dependency: " + request);
			}
			return originalLoad.call(this, request, parent, isMain);
		};
		const { sign } = await import(${JSON.stringify(SIGN_PATH)});
		const pfx = new Uint8Array(readFileSync(${JSON.stringify(PFX_FIXTURE)}));
		const out = await sign({
			input: { xml: "<root><data>optional pkcs11 off</data></root>", placement: "root-append" },
			signer: { pfx, password: "testpass" },
		});
		if (!out.includes("<ds:Signature")) throw new Error("signature missing");
		process.stdout.write("OK");
	`;
	const r = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
		cwd: join(import.meta.dirname, ".."),
		encoding: "utf8",
	});
	assert.equal(r.status, 0, r.stderr || r.stdout);
	assert.match(r.stdout, /OK/);
});

test("pkcs11 — XAdES round-trip via akıllı kart",
	{ skip: !enabled && skipMsg },
	async () => {
		const h = openPkcs11({ modulePath: MODULE!, pin: PIN });
		try {
			const xml = "<root><data>pkcs11 xades</data></root>";
			const signed = await sign({
				input: { xml, placement: "root-append" },
				signer: { pkcs11: h, label: LABEL },
			});
			const r = await verify(signed);
			assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
			if (!r.valid) return;
			assert.equal(r.level, "BES");
		} finally {
			h.close();
		}
	});

test("pkcs11 — CAdES round-trip via akıllı kart",
	{ skip: !enabled && skipMsg },
	async () => {
		const h = openPkcs11({ modulePath: MODULE!, pin: PIN });
		try {
			const data = new TextEncoder().encode("pkcs11 cades");
			const cms = await cadesSign({ data, signer: { pkcs11: h, label: LABEL } });
			const r = await cadesVerify(cms);
			assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
			if (!r.valid) return;
			assert.equal(r.level, "BES");
		} finally {
			h.close();
		}
	});

test("pkcs11 — PAdES round-trip via akıllı kart",
	{ skip: !enabled && skipMsg },
	async () => {
		const h = openPkcs11({ modulePath: MODULE!, pin: PIN });
		try {
			const doc = await PDFDocument.create();
			doc.addPage([200, 200]).drawText("pkcs11 pades", { x: 30, y: 100, size: 14 });
			const pdf = new Uint8Array(await doc.save({ useObjectStreams: false }));
			const signed = await padesSign({ pdf, signer: { pkcs11: h, label: LABEL } });
			const r = await padesVerify(signed);
			assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
			if (!r.valid) return;
			assert.equal(r.level, "BES");
		} finally {
			h.close();
		}
	});
