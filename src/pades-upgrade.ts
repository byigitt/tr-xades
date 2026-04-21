// PAdES seviye yükseltici. v0.5.0'da yalnız B-T.
//
// Akış: PDF'ten CMS'i çıkar → cadesUpgrade({to:"T"}) → /Contents placeholder'a
// yeni CMS'i yaz. Placeholder boyutu sabit (spliceSignature length-preserving);
// CAdES-T CMS ~5-7KB + TS token ~5-6KB = ~12KB, default 16KB placeholder'a sığar.
// Yetmezse padesSign({signatureSize:…}) ile büyütülmeli.
//
// LT/LTA v0.5.x'a — DSS dict + DocTimeStamp PDF-level ek, bağımsız iterasyon.

import { cadesUpgrade } from "./cades-upgrade.ts";
import { extractCms, spliceSignature } from "./pades-core.ts";

export type PadesUpgradeOptions = {
	pdf: Uint8Array;
	to: "T";
	tsa?: { url?: string; policyOid?: string };
};

export async function padesUpgrade(opts: PadesUpgradeOptions): Promise<Uint8Array> {
	const cms = extractCms(opts.pdf);
	const upgraded = await cadesUpgrade({
		bytes: cms,
		to: "T",
		...(opts.tsa !== undefined && { tsa: opts.tsa }),
	});
	return spliceSignature(opts.pdf, upgraded);
}
