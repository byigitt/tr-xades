import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateChain } from "../src/chain.ts";
import { loadPfx } from "../src/pfx.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

// Not: test.p12 self-signed RSA ama BasicConstraints CA:TRUE yok, bu yüzden
// pkijs chain engine "kendi içinde root-anchor" olarak kabul etmiyor — RFC 5280
// gerçeği. Gerçek TR mali mühür chain fixture'ına kadar self-signed pozitif
// testi atlıyoruz; negatif test (empty trust store) aşağıda.

test("validateChain — empty trust store → invalid",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const b = await loadPfx(new Uint8Array(readFileSync(FIXTURE)), "testpass");
		const r = await validateChain({ leaf: b.certificate, roots: [] });
		assert.equal(r.valid, false);
		if (r.valid) return;
		assert.match(r.reason, /trust|path|anchor|root/i);
	});
