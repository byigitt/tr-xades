// tr-xades örnek: UBL-TR faturasını XAdES-BES ile imzala, stdout'a yaz.
// Çalıştır:
//   pnpm run example:bes > invoice-signed.xml
// Ön koşul: reference/fixtures/test.p12 (bkz. reference/README.md).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { sign } from "../src/sign.ts";

const root = join(import.meta.dirname, "..");
const pfx = new Uint8Array(readFileSync(join(root, "reference/fixtures/test.p12")));
const xml = readFileSync(join(root, "reference/fixtures/sample-invoice.xml"), "utf8");

const signed = await sign({
	input: { xml, placement: "ubl-extension" },
	signer: { pfx, password: "testpass" },
	signingTime: new Date(),
	productionPlace: { city: "Ankara", country: "TR" },
	commitmentType: "proof-of-origin",
});

process.stdout.write(signed);
