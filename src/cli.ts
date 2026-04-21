#!/usr/bin/env node
// tr-esign CLI — minimal argv parse, dependency yok.
//
// Kullanım:
//   tr-esign <format> <action> [--flag value]*
//   format : xades | cades | pades
//   action : sign | verify | upgrade
//
// Örnekler:
//   tr-esign xades sign    --pfx m.p12 --password X --in in.xml --out out.xml --policy P3
//   tr-esign xades verify  --in signed.xml
//   tr-esign xades upgrade --in signed.xml --to T --out out.xml --tsa http://tzd.kamusm.gov.tr
//   tr-esign cades sign    --pfx m.p12 --password X --in data.bin --out cms.p7s --detached
//   tr-esign cades verify  --in cms.p7s [--content data.bin]
//   tr-esign pades sign    --pfx m.p12 --password X --in in.pdf --out signed.pdf
//   tr-esign pades verify  --in signed.pdf

import { readFileSync, writeFileSync } from "node:fs";

type Args = { positional: string[]; flags: Map<string, string>; bools: Set<string> };

function parseArgs(argv: string[]): Args {
	const positional: string[] = [];
	const flags = new Map<string, string>();
	const bools = new Set<string>();
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!;
		if (!a.startsWith("--")) { positional.push(a); continue; }
		const key = a.slice(2);
		const next = argv[i + 1];
		if (next === undefined || next.startsWith("--")) { bools.add(key); }
		else { flags.set(key, next); i++; }
	}
	return { positional, flags, bools };
}

function req(a: Args, key: string): string {
	const v = a.flags.get(key);
	if (v === undefined) { die(`--${key} zorunlu`); }
	return v;
}

function readSigner(a: Args): { pfx: Uint8Array; password: string } {
	const pfxPath = req(a, "pfx");
	const password = a.flags.get("password") ?? process.env.TR_ESIGN_PFX_PASS ?? "";
	return { pfx: new Uint8Array(readFileSync(pfxPath)), password };
}

function out(a: Args, data: Uint8Array | string): void {
	const path = a.flags.get("out");
	const buf = typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
	if (path) writeFileSync(path, buf);
	else process.stdout.write(buf);
}

async function cmdXades(action: string, a: Args): Promise<void> {
	if (action === "sign") {
		const { sign } = await import("./sign.ts");
		const xml = readFileSync(req(a, "in"), "utf8");
		const placement = (a.flags.get("placement") ?? "ubl-extension") as "ubl-extension" | "root-append" | "ubl-ma3-compat";
		const signed = await sign({
			input: { xml, placement },
			signer: readSigner(a),
			...(a.flags.get("policy") && { policy: a.flags.get("policy") as "P2" | "P3" | "P4" }),
		});
		out(a, signed);
	} else if (action === "verify") {
		const { verify } = await import("./verify.ts");
		const xml = readFileSync(req(a, "in"), "utf8");
		const r = await verify(xml);
		console.log(JSON.stringify(r, null, 2));
		process.exit(r.valid ? 0 : 1);
	} else if (action === "upgrade") {
		const { upgrade } = await import("./upgrade.ts");
		const xml = readFileSync(req(a, "in"), "utf8");
		const to = req(a, "to") as "T" | "LT" | "LTA";
		const tsa = a.flags.get("tsa");
		const opts = to === "T" || to === "LTA"
			? { xml, to, ...(tsa && { tsa: { url: tsa } }) }
			: { xml, to, chain: [] as Uint8Array[] };
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const upgraded = await upgrade(opts as any);
		out(a, upgraded);
	} else die(`xades: bilinmeyen action: ${action}`);
}

async function cmdCades(action: string, a: Args): Promise<void> {
	if (action === "sign") {
		const { cadesSign } = await import("./cades-sign.ts");
		const data = new Uint8Array(readFileSync(req(a, "in")));
		const cms = await cadesSign({
			data, signer: readSigner(a),
			contentIncluded: !a.bools.has("detached"),
			...(a.flags.get("policy") && { policy: a.flags.get("policy") as "P2" | "P3" | "P4" }),
		});
		out(a, cms);
	} else if (action === "verify") {
		const { cadesVerify } = await import("./cades-verify.ts");
		const bytes = new Uint8Array(readFileSync(req(a, "in")));
		const content = a.flags.get("content");
		const r = await cadesVerify(bytes, content ? { detachedContent: new Uint8Array(readFileSync(content)) } : {});
		console.log(JSON.stringify(r, null, 2));
		process.exit(r.valid ? 0 : 1);
	} else if (action === "upgrade") {
		const { cadesUpgrade } = await import("./cades-upgrade.ts");
		const bytes = new Uint8Array(readFileSync(req(a, "in")));
		const to = req(a, "to") as "T" | "LT" | "LTA";
		const tsa = a.flags.get("tsa");
		const opts = to === "LT"
			? { bytes, to, chain: [] as Uint8Array[] }
			: { bytes, to, ...(tsa && { tsa: { url: tsa } }) };
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		out(a, await cadesUpgrade(opts as any));
	} else die(`cades: bilinmeyen action: ${action}`);
}

async function cmdPades(action: string, a: Args): Promise<void> {
	if (action === "sign") {
		const { padesSign } = await import("./pades-sign.ts");
		const pdf = new Uint8Array(readFileSync(req(a, "in")));
		const signed = await padesSign({
			pdf, signer: readSigner(a),
			...(a.flags.get("reason") && { reason: a.flags.get("reason") }),
			...(a.flags.get("signer-name") && { signerName: a.flags.get("signer-name") }),
			...(a.flags.get("policy") && { policy: a.flags.get("policy") as "P2" | "P3" | "P4" }),
		});
		out(a, signed);
	} else if (action === "verify") {
		const { padesVerify } = await import("./pades-verify.ts");
		const pdf = new Uint8Array(readFileSync(req(a, "in")));
		const r = await padesVerify(pdf);
		console.log(JSON.stringify(r, null, 2));
		process.exit(r.valid ? 0 : 1);
	} else if (action === "upgrade") {
		const { padesUpgrade } = await import("./pades-upgrade.ts");
		const pdf = new Uint8Array(readFileSync(req(a, "in")));
		const to = req(a, "to") as "T" | "LT" | "LTA";
		const tsa = a.flags.get("tsa");
		const opts = to === "LT"
			? { pdf, to, chain: [] as Uint8Array[] }
			: { pdf, to, ...(tsa && { tsa: { url: tsa } }) };
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		out(a, await padesUpgrade(opts as any));
	} else die(`pades: bilinmeyen action: ${action}`);
}

function usage(): void {
	console.error(`tr-esign — Türkiye profili XAdES/CAdES/PAdES/ASiC imza CLI

KULLANIM
  tr-esign <format> <action> [--flag value]*

FORMATLAR
  xades  cades  pades

AKSİYONLAR
  sign     --pfx <p12> [--password <pw>] --in <input> [--out <file>] [--policy P2|P3|P4]
  verify   --in <signed> [--content <data> (cades detached)]   → stdout JSON
  upgrade  --in <signed> --to T|LT|LTA [--tsa <url>] [--out <file>]

ORTAK BAYRAK
  --out <file>    yoksa stdout
  --password env  TR_ESIGN_PFX_PASS'den de okunur

ÖRNEK
  tr-esign xades sign    --pfx m.p12 --password X --in fatura.xml --out imzali.xml --policy P3
  tr-esign pades verify  --in imzali.pdf
  tr-esign cades upgrade --in bes.p7s --to T --tsa http://tzd.kamusm.gov.tr --out t.p7s`);
}

function die(msg: string): never {
	console.error(`hata: ${msg}`);
	console.error("");
	usage();
	process.exit(2);
}

async function main(): Promise<void> {
	const argv = process.argv.slice(2);
	if (argv.length === 0 || argv.includes("-h") || argv.includes("--help")) {
		usage();
		process.exit(argv.length === 0 ? 2 : 0);
	}
	const [format, action, ...rest] = argv;
	const args = parseArgs(rest);
	if (format === "xades") await cmdXades(action!, args);
	else if (format === "cades") await cmdCades(action!, args);
	else if (format === "pades") await cmdPades(action!, args);
	else die(`bilinmeyen format: ${format}`);
}

main().catch((e: Error) => {
	console.error(`hata: ${e.message}`);
	process.exit(1);
});
