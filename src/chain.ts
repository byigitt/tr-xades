// X.509 chain validation (RFC 5280 minimal, pkijs CertificateChainValidationEngine
// üstünde). Sertifika bundle'ı (TR Kamu SM kökleri vs.) kullanıcıdan gelir —
// redistribution/versioning sorunları yüzünden kütüphane kökleri embed etmez.
// loadKamuSmRoots() çalıştırma zamanında fetch eder.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

export type ChainResult =
	| { valid: true; path: Uint8Array[] } // DER list, leaf → root
	| { valid: false; reason: string; code?: number };

export type ValidateOptions = {
	leaf: Uint8Array; // end-entity DER
	intermediates?: Uint8Array[];
	roots: Uint8Array[]; // trusted anchors
	checkDate?: Date;
	crls?: Uint8Array[];
	ocspResponses?: Uint8Array[];
};

export async function validateChain(o: ValidateOptions): Promise<ChainResult> {
	try {
		const leaf = parseCert(o.leaf);
		const intermediates = (o.intermediates ?? []).map(parseCert);
		const roots = o.roots.map(parseCert);
		const crls = (o.crls ?? []).map((d) => new pkijs.CertificateRevocationList({ schema: asn1js.fromBER(toAB(d)).result }));
		const ocsps = (o.ocspResponses ?? []).map((d) => {
			const resp = new pkijs.OCSPResponse({ schema: asn1js.fromBER(toAB(d)).result });
			if (!resp.responseBytes) throw new Error("OCSP cevabı basic response içermiyor");
			const basic = asn1js.fromBER(toAB(new Uint8Array(resp.responseBytes.response.valueBlock.valueHexView))).result;
			return new pkijs.BasicOCSPResponse({ schema: basic });
		});

		const engine = new pkijs.CertificateChainValidationEngine({
			certs: [leaf, ...intermediates],
			trustedCerts: roots,
			...(crls.length ? { crls } : {}),
			...(ocsps.length ? { ocsps } : {}),
			...(o.checkDate ? { checkDate: o.checkDate } : {}),
		});
		const r = await engine.verify();
		if (!r.result) return { valid: false, reason: r.resultMessage ?? "chain invalid", code: r.resultCode };
		const path = (r.certificatePath ?? []).map((c) => new Uint8Array(c.toSchema().toBER()));
		return { valid: true, path };
	} catch (e) {
		return { valid: false, reason: e instanceof Error ? e.message : String(e) };
	}
}

// Kamu SM SertifikaDeposu: ~200 kök+ara sertifika, XML wrapper, base64 içerik.
// XML'de her <Sertifika> → <X509Data>base64 DER</X509Data> taşır.
// Runtime'da fetch + parse; kütüphane embed etmez.
export async function loadKamuSmRoots(
	url = "http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml",
): Promise<Uint8Array[]> {
	const r = await fetch(url);
	if (!r.ok) throw new Error(`Kamu SM deposu HTTP ${r.status}`);
	const xml = await r.text();
	// Basit regex — şemaya sıkı sıkıya bağlı değil; yalnızca X509Certificate/
	// base64 içerikleri yakalar (<Sertifika>…<Deger>base64</Deger>).
	const out: Uint8Array[] = [];
	const re = /<(?:X509Certificate|Deger|CertificateValue)>([^<]+?)<\/(?:X509Certificate|Deger|CertificateValue)>/g;
	for (const m of xml.matchAll(re)) {
		const b64 = m[1]!.replace(/\s+/g, "");
		try { out.push(new Uint8Array(Buffer.from(b64, "base64"))); }
		catch { /* skip bad entry */ }
	}
	return out;
}

function parseCert(der: Uint8Array): pkijs.Certificate {
	return new pkijs.Certificate({ schema: asn1js.fromBER(toAB(der)).result });
}
function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
