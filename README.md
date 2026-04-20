# tr-xades

Türkiye profili **XAdES** elektronik imza kütüphanesi. Node 20+, TypeScript.
Clean-room — ETSI spec + kamuya açık TR dokümanları + MIT lisanslı bağımlılıklar.

```
Kapsam:    XAdES-BES / -EPES / -T / -LT / -LTA
           Enveloping + Enveloped (UBL-TR e-Fatura) + Detached + Counter-signature + Multi-sig
Signer:    PFX (PKCS#12) veya pkcs8 + X.509 DER
Algo:      RSA-PKCS1-v1_5 & ECDSA × SHA-256/384/512, EXC-C14N / C14N 1.0
Policy:    TR P2/P3/P4 v1 (Elektronik İmza Kullanım Profilleri Rehberi)
TSA:       RFC 3161 generic + Kamu SM varsayılan
Interop:   MA3 2.3.11.8 fixtures (verify) + MA3 verifier accepts ubl-ma3-compat
```

## Kurulum

```bash
pnpm add tr-xades
```

## Hızlı bakış

### İmzala

```ts
import { readFileSync } from "node:fs";
import { sign } from "tr-xades/sign";

const pfx = new Uint8Array(readFileSync("./mali-muhur.pfx"));
const invoice = readFileSync("./invoice.xml", "utf8");

const signed = await sign({
  input: { xml: invoice, placement: "ubl-extension" },
  signer: { pfx, password: process.env.PFX_PASS! },
  policy: "P3",                         // UBL-TR / e-Fatura TR profili → EPES
  productionPlace: { city: "İstanbul", country: "TR" },
  commitmentType: "proof-of-origin",
});
```

### Doğrula

```ts
import { verify } from "tr-xades/verify";

const r = await verify(signed);
if (!r.valid) throw new Error(r.reason);

console.log(r.level);           // "EPES"
console.log(r.signer.subject);  // "CN=Örnek Satıcı A.Ş.,…"
console.log(r.signedAt);        // Date | undefined
```

### Seviye yükselt

```ts
import { upgrade } from "tr-xades/upgrade";

const t   = await upgrade({ xml: signed, to: "T",  tsa: { url: "http://tzd.kamusm.gov.tr" } });
const lt  = await upgrade({ xml: t,      to: "LT", chain: [leafDer, intermediateDer, rootDer] });
const lta = await upgrade({ xml: lt,     to: "LTA" });
```

## API

### `sign(opts): Promise<string>` — `src/sign.ts`

| field | type | default | not |
|---|---|---|---|
| `input.xml + placement` | `{xml, "ubl-extension" \| "root-append"}` | | W3C enveloped (URI="" + enveloped-signature transform) |
| `input.xml + placement` | `{xml, "ubl-ma3-compat"}` | | UBL envelope + enveloping-embedded (MA3 interop) |
| `input.bytes + mimeType` | `{bytes, mimeType}` | | Enveloping (data ds:Object içinde) |
| `input.uri + data + mimeType` | `{uri, data, mimeType}` | | Detached (external ref) |
| `signer.pfx + password` | `{pfx: Uint8Array, password}` | | PKCS#12 |
| `signer.pkcs8 + certificate` | `{pkcs8, certificate}` | | Direct (signatureAlgorithm zorunlu) |
| `policy` | `"P2"\|"P3"\|"P4" \| Policy` | undefined | varsa EPES |
| `digestAlgorithm` | `"SHA-256"\|"SHA-384"\|"SHA-512"` | `"SHA-256"` | |
| `signatureAlgorithm` | `"RSA-SHA256"\|…\|"ECDSA-SHA256"\|…` | anahtar+digest'ten türetilir | |
| `c14nAlgorithm` | `"exc-c14n"\|"c14n10"\|…` | `"exc-c14n"` | UBL-TR uyumu |
| `signingTime` | `Date \| null` | `new Date()` | `null` = hiç emit etme |
| `productionPlace` | `{city?, state?, postalCode?, country?}` | | |
| `commitmentType` | `"proof-of-origin"\|…` | | ETSI OID'e map |
| `signerRole` | `{ claimed: string[] }` | | |

### `verify(xml, opts?): Promise<VerifyResult>` — `src/verify.ts`

```ts
type VerifyResult =
  | { valid: true; level: "XMLDSig"|"BES"|"EPES"|"T"|"LT"|"LTA";
      signer: { subject, issuer, serialHex, notBefore, notAfter };
      signedAt?: Date;
      counterSignatures?: SignerInfo[];    // XAdES CounterSignature varsa
      allSignatures?: PerSignatureResult[]; // 2+ top-level (paralel) imza varsa
    }
  | { valid: false; reason: string; detail?: unknown };

type VerifyOptions = {
  // Detached imza veya external URI referanslar için.
  resolver?: (uri: string) => Uint8Array | Node | null | Promise<...>;
};
```

XMLDSig §3.2 core validation: tüm Reference digest'leri yeniden hesaplanır +
SignedInfo c14n + SignatureValue kriptografik doğrulanır. Seviye tespiti: yapıya
göre (QP, SigPolicy, SignatureTimeStamp, Complete*Refs/CertValues, ArchiveTS).

Counter-sig'ler recursive doğrulanır — geçerli olanların signer'ı `counterSignatures`'ta.
Paralel imzalar (2+ top-level) `allSignatures`'ta her biri ayrı rapor.

**Scope notu:** cert chain validation default KAPALI. İsterseniz
`validateChain()` ile kendi trust bundle'ınızda doğrulayın.

### `upgrade(opts): Promise<string>` — `src/upgrade.ts`

Discriminated union, `to`'ya göre:

```ts
{ xml, to: "T",   tsa?: { url?, policyOid? } }
{ xml, to: "LT",  chain: Uint8Array[], crls?: Uint8Array[], ocsps?: Uint8Array[] }
{ xml, to: "LTA", tsa?: { url?, policyOid? } }
```

Kaskad yok: BES→T→LT→LTA sırasını kullanıcı kurar.

### `counterSign(opts): Promise<string>` — `src/counter-sign.ts`

```ts
await counterSign({
  xml: signedXml,
  signer: { pfx, password },
  parentSignatureId: "Signature-Id-...",  // opsiyonel; yoksa ilk ds:Signature
  // aynı sign() opsiyonları: signingTime, productionPlace, commitmentType, ...
});
```

Mevcut bir `ds:Signature`'a karşı imza atar. Yeni imza parent'ın
`ds:SignatureValue`'suna referans verir (Type=`http://uri.etsi.org/01903#CountersignedSignature`)
ve `xades:UnsignedSignatureProperties/xades:CounterSignature` altına yerleştirilir.

### Paralel (multi) imza

Ayrı fonksiyon yok — `sign()` tekrar çağırın (ubl-ma3-compat modunda her sig kendi
`ds:Object`'ini kullanır, bağımsızdır). `verify()` primary olarak ilk sig'i raporlar,
2+ varsa `allSignatures[]` ile hepsini verir.

### Yardımcı modüller

| modül | içerik |
|---|---|
| `src/pfx.ts` | `loadPfx(bytes, password)` — PKCS#12 → `{privateKey: {pkcs8, algorithm}, certificate, chain}` |
| `src/crypto.ts` | `digest`, `sign`, `verify`, `importPrivateKey`, `importPublicKeyFromCert` (WebCrypto wrappers) |
| `src/c14n.ts` | `canonicalize(node, alg)` — xmldsigjs üstünde, MA3 uyumlu xmlns inheritance |
| `src/policy.ts` | `trPolicy("P2"\|"P3"\|"P4")` — TR policy OID + doc SHA-256 |
| `src/tsp.ts` | RFC 3161: `buildRequest`, `parseResponse`, `getTimestamp` |
| `src/ocsp.ts` | RFC 6960: `checkOcsp`, AIA'dan responder URL çıkarımı |
| `src/crl.ts` | `fetchCrl`, `parseCrl`, `isRevoked`, `crlUrlsFromCert` |
| `src/chain.ts` | `validateChain`, `loadKamuSmRoots` (runtime fetch) |

## Kapsam dışı

- **CAdES / PAdES / ASiC** — yalnız XAdES (v0.3+ adayı).
- **PKCS#11 / akıllı kart** — yumuşak anahtar (PFX/pkcs8). Ayrı paket planlı (`tr-xades-pkcs11`).
- **Mobil İmza** (Turkcell / Vodafone / TT-MSS) — operatör entegrasyonu v1.x.
- **Browser** — Node-only. Tarayıcıda PKCS#11 + fs olmuyor.
- **CLI** — library-only.

## Güvenlik

- `tr-xades` özel anahtarı disk'te saklamaz; `pfx` bayt dizisi olarak geçer, bellekte açılır.
- `verify()` sonucunda `valid: true` dönmesi **yalnızca** şu demek:
  1. ds:SignedInfo bütünlüğü (cryptographic signature) sağlanmış,
  2. tüm ds:Reference digest'leri eşleşiyor,
  3. SignedProperties varsa SigningCertificate/CertDigest tutarlı.
- **Cert chain ve revocation kontrolü ayrıdır.** Kendi trust bundle'ınızda `validateChain()` ile yapın.
- Bir XAdES imzasının "hukuki geçerliliği", kullanılan sertifikanın niteliği (nitelikli elektronik sertifika, NES) ve imza politikasına uygunlukla ilgilidir — kütüphanenin yapısal geçerlik kontrolü ile karıştırılmamalıdır.

## Interop (MA3 2.3.11.8)

| Senaryo | tr-xades verify | MA3 verifier |
|---|---|---|
| MA3 enveloping fixture | ✅ valid | — |
| MA3 enveloped-embedded fixture | ✅ valid | — |
| MA3 detached fixture (`sample-invoice.xml` URI) | ✅ valid (w/ `resolver`) | — |
| tr-xades enveloping BES | — | ✅ temel doğru — cert chain ayrı |
| tr-xades **`placement: "ubl-ma3-compat"`** | — | ✅ **temel doğru** — cert chain ayrı |
| tr-xades W3C enveloped (`ubl-extension`) | — | ❌ MA3 farklı konvansiyon (yalnız `ubl-ma3-compat` kullanın) |

MA3 verifier self-signed test cert'imizi reddediyor (Kamu SM bundle'ında yok) —
gerçek mali mühür cert ile kalkacak beklenen sorun. Detaylar için
`reference/driver/Ma3Verify.java` ve `reference/verify.sh`.

## Geliştirme

```bash
pnpm install
pnpm test                    # offline: 32 test
TR_XADES_LIVE_TSA=1 pnpm test  # + canlı FreeTSA integration
pnpm exec tsgo --noEmit
pnpm exec oxlint
```

MA3 referans fixture'larını yeniden üretmek için: bkz. `reference/README.md`.

## Lisans

MIT. `LICENSE` dosyası.

## Yasal not

Bu proje TÜBİTAK BİLGEM MA3 API kaynağının reverse engineering sonucu değildir.
ETSI standartları + kamuya açık TR dokümanları + MIT lisanslı bağımlılıklar
üzerine inşa edilmiştir. "Uyum Değerlendirme" (GİB entegratörlük vb.) gereken
senaryolarda kütüphane için uygunluk denetimini kullanıcı yürütür.
