# tr-esign

Türkiye için **XAdES + CAdES + PAdES + ASiC** elektronik imza kütüphanesi.
Tek paket, tek tip `VerifyResult`, paylasılan CMS çekirdeği. Node 20+, TypeScript.
Clean-room — ETSI spec + kamuya açık TR dokümanları + MIT lisanslı bağımlılıklar.

| Format | Ne zaman? | API |
|---|---|---|
| **XAdES** | XML/UBL-TR (e-Fatura, e-İrşaliye, e-Bilet)                    | `tr-esign/sign` + `verify` + `upgrade` |
| **CAdES** | İkili veri, e-reçete, detached özet imza (CMS/PKCS#7 ASN.1) | `tr-esign/cades-sign` + `cades-verify` + `cades-upgrade` |
| **PAdES** | PDF doküman imzası (fatura PDF arşivi, resmi yazı)       | `tr-esign/pades-sign` + `pades-verify` + `pades-upgrade` |
| **ASiC** | İmza + veri tek zip (ASiC-S/-E)                           | `tr-esign/asic` |

```
XAdES:     BES / EPES / T / LT / LTA
           Enveloping + Enveloped (UBL-TR e-Fatura) + Detached + Counter-signature + Multi-sig
CAdES:     BES / EPES / T / LT / LTA
           CMS/PKCS#7 ASN.1 DER, attached + detached; RFC 5652 / ETSI TS 101 733
PAdES:     B-B / EPES / B-T / B-LT / B-LTA
           PDF incremental update, /SubFilter /ETSI.CAdES.detached;
           DSS + DocTimeStamp; ETSI EN 319 142-1 §5.3/5.4/5.5
ASiC:      ASiC-S + ASiC-E zip konteyner; ETSI EN 319 162-1 §A.1
Signer:    PFX (PKCS#12) veya pkcs8 + X.509 DER
Algo:      RSA-PKCS1-v1_5 & ECDSA × SHA-256/384/512, EXC-C14N / C14N 1.0
Policy:    TR P2/P3/P4 v1 (Elektronik İmza Kullanım Profilleri Rehberi)
TSA:       RFC 3161 generic + Kamu SM varsayılan
Interop:   MA3 2.3.11.8 fixtures (verify) + MA3 verifier accepts ubl-ma3-compat
```

## Kurulum

```bash
pnpm add tr-esign
```

## Hızlı bakış — her format bir örnekte

Tüm örneklerde ortak: PFX (PKCS#12) yükle, hedef formatın `sign()` /
`upgrade()` / `verify()` üçlüsünü çağır. `verify()` her formatta aynı
`VerifyResult` tipini döner.

```ts
import { readFileSync } from "node:fs";
const pfx = new Uint8Array(readFileSync("./mali-muhur.pfx"));
const signer = { pfx, password: process.env.PFX_PASS! };
```

### XAdES — UBL-TR / e-Fatura

```ts
import { sign } from "tr-esign/sign";
import { verify } from "tr-esign/verify";
import { upgrade } from "tr-esign/upgrade";

const signed = await sign({
  input: { xml: readFileSync("./invoice.xml", "utf8"), placement: "ubl-extension" },
  signer,
  policy: "P3",                         // TR profili → EPES
  productionPlace: { city: "İstanbul", country: "TR" },
  commitmentType: "proof-of-origin",
});
const r = await verify(signed);         // { valid, level, signer, … }
const t = await upgrade({ xml: signed, to: "T", tsa: { url: "http://tzd.kamusm.gov.tr" } });
```

### CAdES — CMS/PKCS#7 ikili imza

```ts
import { cadesSign } from "tr-esign/cades-sign";
import { cadesVerify } from "tr-esign/cades-verify";

const data = readFileSync("./recete.bin");
const cms = await cadesSign({ data, signer, policy: "P3", contentIncluded: false });
const r = await cadesVerify(cms, { detachedContent: data });
```

### PAdES — PDF e-imza

```ts
import { padesSign } from "tr-esign/pades-sign";
import { padesVerify } from "tr-esign/pades-verify";
import { padesUpgrade } from "tr-esign/pades-upgrade";

const pdf = new Uint8Array(readFileSync("./fatura.pdf"));
const signed = await padesSign({ pdf, signer, reason: "Onay", policy: "P3" });
const lta = await padesUpgrade({ pdf: signed, to: "LTA", tsa: { url: "http://tzd.kamusm.gov.tr" } });
const r = await padesVerify(lta);
```

### ASiC — imza + veri tek zip

```ts
import { createAsic, readAsic } from "tr-esign/asic";

const data = readFileSync("./fatura.xml");
const sig  = await sign({ input: { xml: data.toString("utf8"), placement: "ubl-extension" }, signer });
const asic = createAsic({
  type: "asic-s",
  data: { name: "fatura.xml", bytes: new Uint8Array(data) },
  signature: { bytes: new TextEncoder().encode(sig), format: "xades" },
});
const { type, dataFiles, signatures } = readAsic(asic);
```

Her formatın detaylı API'si aşağıda.

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

### CAdES (CMS / PKCS#7 ASN.1 imza)

XML tabanlı XAdES'in karşılığı; ikili veri (e-reçete, binary doküman, detached
özet imza). Çıktı DER-encoded CMS SignedData (ContentInfo sarıcılı).

```ts
import { cadesSign } from "tr-esign/cades-sign";
import { cadesVerify } from "tr-esign/cades-verify";
import { cadesUpgrade } from "tr-esign/cades-upgrade";

const pfx = new Uint8Array(readFileSync("./mali-muhur.pfx"));
const data = readFileSync("./recete.bin");

// Attached (içerik imza içinde)
const bes = await cadesSign({
  data,
  signer: { pfx, password: process.env.PFX_PASS! },
  policy: "P3",                           // TR profili → EPES
  commitmentType: "proof-of-origin",
});

// Detached (içerik dışta; verify sırasında detachedContent verilir)
const detached = await cadesSign({
  data, signer: { pfx, password },
  contentIncluded: false,
});

// Doğrulama — attached kendi kendine; detached için harici veri verilir
const r = await cadesVerify(bes);
const rDet = await cadesVerify(detached, { detachedContent: data });

// Seviye yükseltme — T, LT, LTA zincirlenebilir.
const t   = await cadesUpgrade({ bytes: bes, to: "T", tsa: { url: "http://tzd.kamusm.gov.tr" } });
const lt  = await cadesUpgrade({ bytes: t,   to: "LT", chain: [leafDer, intDer, rootDer], ocsps, crls });
const lta = await cadesUpgrade({ bytes: lt,  to: "LTA", tsa: { url: "http://tzd.kamusm.gov.tr" } });
```

- **T**: `signature-time-stamp` (ETSI §6.1.1) — SignerInfo.signature üzerinde RFC 3161.
- **LT**: `certificate-values` + `revocation-values` (§6.2) — tüm zincir + CRL/OCSP gömülür.
- **LTA**: `archive-time-stamp-v2` (§6.4.1, OID 1.2.840.113549.1.9.16.2.48) — SignedData alınırsa
  concat hash’i üzerinde RFC 3161. Detached için `detachedContent` geçilir.

VerifyResult XAdES ile aynı tip; seviye signedAttrs/unsignedAttrs inceleyerek
türetilir (BES / EPES / T / LT / LTA).

### ASiC — imzalı zip konteyner (ETSI EN 319 162-1)

XAdES veya CAdES imzası + orijinal veri dosyalarını tek bir zip’e paketler.
İmza üretme ile paketleme birbirinden bağımsız: **önce `sign()` / `cadesSign()`,
sonra `createAsic()`**.

```ts
import { createAsic, readAsic } from "tr-esign/asic";
import { cadesSign } from "tr-esign/cades-sign";

const data = readFileSync("./recete.bin");
const sig = await cadesSign({ data, signer, contentIncluded: false });

// ASiC-S — tek veri + tek imza
const asicS = createAsic({
  type: "asic-s",
  data: { name: "recete.bin", bytes: data },
  signature: { bytes: sig, format: "cades" },
});
writeFileSync("./recete.asice", asicS);

// ASiC-E — çok dosya + (ops.) manifest
const asicE = createAsic({
  type: "asic-e",
  dataFiles: [
    { name: "fatura.xml", bytes: faturaXml },
    { name: "ek.pdf", bytes: ekPdf },
  ],
  signatures: [
    { bytes: xadesSig, format: "xades" },
  ],
});

// Okuma
const { type, dataFiles, signatures, manifests } = readAsic(asicS);
```

Layout (EN 319 162-1 §A.1):
- `mimetype` — FIRST entry, STORED, `application/vnd.etsi.asic-s+zip` veya `asic-e+zip`
- Kök: veri dosyaları (İ-S tek, E çok)
- `META-INF/signatures.xml` (XAdES) veya `signature.p7s` (CAdES). E için `NNN` indeks.

### PAdES — PDF e-imza (ETSI EN 319 142-1)

PDF'e incremental update ile imza dictionary, AcroForm ve CMS signature
eklenir. Orijinal bayt bayt korunur (PAdES gereği). CAdES CMS çekirdeği
reuse edilir — detached sig + ByteRange bytes üzerinde messageDigest.

```ts
import { padesSign } from "tr-esign/pades-sign";
import { padesVerify } from "tr-esign/pades-verify";
import { padesUpgrade } from "tr-esign/pades-upgrade";

const pdf = readFileSync("./fatura.pdf");
const pfx = readFileSync("./mali-muhur.pfx");

// B-B / EPES (policy verildiğinde EPES)
const signed = await padesSign({
  pdf: new Uint8Array(pdf),
  signer: { pfx: new Uint8Array(pfx), password: process.env.PFX_PASS! },
  reason: "E-Fatura onayı",
  signerName: "Barış Y.",
  location: "Ankara",
  policy: "P3",                         // TR profili → EPES
  commitmentType: "proof-of-origin",
  signatureSize: 16384,                 // /Contents placeholder (default 16KB)
});

// Seviye yükseltme — B-T / B-LT / B-LTA zincirlenebilir
const bt  = await padesUpgrade({ pdf: signed, to: "T", tsa: { url: "http://tzd.kamusm.gov.tr" } });
const blt = await padesUpgrade({ pdf: bt,     to: "LT", chain: [leafDer, intDer, rootDer], ocsps, crls });
const lta = await padesUpgrade({ pdf: blt,    to: "LTA", tsa: { url: "http://tzd.kamusm.gov.tr" } });

// Doğrulama
const r = await padesVerify(lta);
// r.valid → boolean, r.level → 'BES'|'EPES'|'T'|'LT'|'LTA', r.signer.subject, ...
```

| Seviye | Nasıl elde edilir | PDF-level yapı |
|---|---|---|
| **B-B**  | `padesSign({ ... })`                   | /Sig dict, /Contents=CMS, /ByteRange |
| **EPES** | `padesSign({ policy: "P3" })`          | + signaturePolicyId CMS signedAttr  |
| **B-T**  | `padesUpgrade({ to:"T", tsa })`        | + CMS signatureTimeStamp unsignedAttr |
| **B-LT** | `padesUpgrade({ to:"LT", chain, … })`   | + /DSS /Certs /CRLs /OCSPs streams    |
| **B-LTA**| `padesUpgrade({ to:"LTA", tsa })`      | + ikinci /Sig /SubFilter ETSI.RFC3161 |

**Layout (EN 319 142-1 §5.3):**
- /Filter /Adobe.PPKLite, /SubFilter /ETSI.CAdES.detached
- /ByteRange [0 b c d] — hash ByteRange dilimleri (/Contents hariç)
- /Contents <HEX> — hex-encoded CMS SignedData (detached, eContent yok)
- /Type /Sig + AcroForm.Fields + Widget annotation
- LT: /DSS dict (PDF Catalog'da) cert/CRL/OCSP streams
- LTA: ayrı /Sig dict /SubFilter /ETSI.RFC3161, /Contents = TSToken

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
- **PKCS#11 / akıllı kart** — yumuşak anahtar (PFX/pkcs8). Ayrı paket planlı (`tr-esign-pkcs11`).
- **Mobil İmza** (Turkcell / Vodafone / TT-MSS) — operatör entegrasyonu v1.x.
- **Browser** — Node-only. Tarayıcıda PKCS#11 + fs olmuyor.
- **CLI** — library-only.

## Güvenlik

- `tr-esign` özel anahtarı disk'te saklamaz; `pfx` bayt dizisi olarak geçer, bellekte açılır.
- `verify()` sonucunda `valid: true` dönmesi **yalnızca** şu demek:
  1. ds:SignedInfo bütünlüğü (cryptographic signature) sağlanmış,
  2. tüm ds:Reference digest'leri eşleşiyor,
  3. SignedProperties varsa SigningCertificate/CertDigest tutarlı.
- **Cert chain ve revocation kontrolü ayrıdır.** Kendi trust bundle'ınızda `validateChain()` ile yapın.
- Bir XAdES imzasının "hukuki geçerliliği", kullanılan sertifikanın niteliği (nitelikli elektronik sertifika, NES) ve imza politikasına uygunlukla ilgilidir — kütüphanenin yapısal geçerlik kontrolü ile karıştırılmamalıdır.

## Interop (MA3 2.3.11.8)

| Senaryo | tr-esign verify | MA3 verifier |
|---|---|---|
| MA3 enveloping fixture | ✅ valid | — |
| MA3 enveloped-embedded fixture | ✅ valid | — |
| MA3 detached fixture (`sample-invoice.xml` URI) | ✅ valid (w/ `resolver`) | — |
| tr-esign enveloping BES | — | ✅ temel doğru — cert chain ayrı |
| tr-esign **`placement: "ubl-ma3-compat"`** | — | ✅ **temel doğru** — cert chain ayrı |
| tr-esign W3C enveloped (`ubl-extension`) | — | ❌ MA3 farklı konvansiyon (yalnız `ubl-ma3-compat` kullanın) |

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
