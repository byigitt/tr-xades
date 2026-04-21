# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). SemVer.

## [0.5.0] — PAdES + repo rename `tr-xades` → `tr-esign`

Dördüncü imza formatı: PAdES (PDF e-imza). Repo ve paket adı XAdES + CAdES
+ ASiC + PAdES kapsamını yansıtmak için `tr-esign`'e taşındı.

### Eklendi — PAdES (ETSI EN 319 142-1)

- **`src/pades-core.ts`** — PDF incremental update primitive'leri:
  `addSignaturePlaceholder`, `readByteRange`, `extractByteRangeBytes`,
  `findContentsPlaceholder`, `extractCms`, `spliceSignature`,
  `SUBFILTER_ETSI_RFC3161`. `@signpdf/placeholder-plain` string-tabanlı
  incremental update kullanır + /ByteRange placeholder'ı actual değerlerle
  rewrite edilir.
- **`src/pades-sign.ts`** — `padesSign(opts)`. PAdES-B-B + EPES.
  Akış: placeholder ekle → ByteRange hesapla →
  `cadesSign({contentIncluded:false})` → /Contents hex'ine splice. CMS core
  reuse (CAdES çıktısı kullanılır). Options: reason/location/contactInfo/
  signerName/signatureSize + CAdES pass-through (policy/commitmentType/
  digestAlgorithm).
- **`src/pades-verify.ts`** — `padesVerify(pdf): VerifyResult`. /ByteRange +
  /Contents çöz, `cadesVerify(cms, {detachedContent})` çağır. Seviye:
  /DSS (PAdES §5.4) → LT, /SubFilter /ETSI.RFC3161 (DocTimeStamp §5.5)
  → LTA, yoksa CAdES level. VerifyResult XAdES/CAdES ile aynı tip.
- **`src/pades-upgrade.ts`** — `padesUpgrade()` discriminated:
  - `to:"T"` — extractCms + cadesUpgrade(T) + splice. Length-preserving.
  - `to:"LT"` — `addDss()` çağırır (aşağıda).
  - `to:"LTA"` — `addDocTimeStamp()` çağırır (aşağıda).
- **`src/pades-dss.ts`** — `addDss(pdf, {certs,crls,ocsps})`. EN 319 142-1
  §5.4 Document Security Store incremental update: her DER → PDF stream
  obj, /DSS dict /Certs/CRLs/OCSPs, güncel Root (+ /DSS ref), yeni xref +
  trailer (/Prev eski offset). Orijinal imza ByteRange'i dokunulmaz.
- **`src/pades-timestamp.ts`** — `addDocTimeStamp(pdf, {tsa, digestAlgorithm})`.
  EN 319 142-1 §5.5: ikinci /Sig dict /SubFilter /ETSI.RFC3161, /Contents =
  RFC 3161 TimeStampToken. addSignaturePlaceholder(subFilter:ETSI.RFC3161)
  + ByteRange hash + getTimestamp + splice.
- **Subpath exports**: `tr-esign/pades-sign`, `tr-esign/pades-verify`,
  `tr-esign/pades-upgrade`.
- **Deps**: `@signpdf/placeholder-plain` + `@signpdf/utils` (MIT).
  `pdf-lib` devDep (test PDF üretimi).

### Değişti

- **Repo + paket yeniden adlandırıldı**: `tr-xades` → `tr-esign`. İsim artık
  XAdES + CAdES + ASiC + PAdES hepsini kapsayan TR e-imza kütüphanesini
  yansıtıyor. GitHub repo rename yapıldı; eski URL 301 redirect. package.json
  description: "Turkey profile XAdES + CAdES + ASiC + PAdES signature
  library — clean-room; ETSI EN 319 132 / TS 101 733 / EN 319 162 /
  EN 319 142 uyumlu".
- **Test fixture DN**: `O=tr-xades test` → `O=tr-esign test`.
  `reference/fixtures/test.p12` ve `test-chain.p12` yeni DN ile regen.
  MA3 fixture'ları yeni cert ile tekrar üretildi.
- **`src/pades-core.ts`** — `readByteRange` + `writeByteRange` çoklu imza
  PDF'lerinde yanlış /ByteRange yakalıyordu; son (en yeni) olanı almak üzere
  düzeltildi (LTA zinciri için kritik).
- **`src/cades-verify.ts`** (v0.4'ten): `certToSignerInfo` export — pades-verify
  CAdES ile ortak VerifyResult için kullanacaktı; asında doğrudan değil,
  cadesVerify çağrısı içinden implicitly reuse ediliyor.

### Bilinen sınırlamalar

- **MA3 CAdES + PAdES cross-verify ertelendi (v0.5+)**: MA3 addSigner ve
  PAdESContainer.sign() online revocation zorunlu kılıyor. Test CA
  placeholder URL'leri ulaşılamadığı için her iki format için de fixture
  üretilemedi. `cades-cross-verify.test.ts` ve gelecek `pades-cross-verify.
  test.ts` fixture varsa doğrular, yoksa skip. Gerçek TR mali mühür PFX
  veya yerel OCSP responder (docker openssl ocsp) ile çalışacak.
- **PAdES LTA /Type**: @signpdf `/Type /Sig` yazıyor; EN 319 142-1 §5.5
  strict `/Type /DocTimeStamp` ister. Adobe/DSS/MA3 ikisini de kabul
  eder. Strict compliance v0.5.x'e.
- **CAdES-LTA ATSv3** (v0.4'ten aktarıldı): v2 yeterli, v3 ats-hash-index
  gerektiğinde eklenir.

## [0.4.0] — CAdES-LT / -LTA + ASiC

Uzun süreli doğrulama + arşivleme (CAdES) ve zip konteyner (ASiC).

### Eklendi

- **CAdES-LT** (`to:"LT"` in `cades-upgrade.ts`):
  - `buildCertValuesAttr(certs)` — ETSI TS 101 733 §6.2.1
    `id-aa-ets-certValues` (1.2.840.113549.1.9.16.2.23). CertificateValues
    ::= SEQUENCE OF Certificate.
  - `buildRevocationValuesAttr({crls, ocsps})` — §6.2.2
    `id-aa-ets-revocationValues` (1.2.840.113549.1.9.16.2.24).
    EXPLICIT [0] crlVals / [1] ocspVals. OCSPResponse DER'i otomatik
    BasicOCSPResponse'a unwrap edilir (spec içi).
  - Paylasılan `addUnsignedAttr()` helper.

- **CAdES-LTA** (`to:"LTA"`):
  - `archive-time-stamp-v2` (OID 1.2.840.113549.1.9.16.2.48),
    ETSI TS 101 733 §6.4.1. Message imprint input: DER(eContent) ||
    DER(certs)* || DER(crls)* || DER(signerInfo alanları, prior ATS hariç).
  - `detachedContent` opt parametresi detached BES/T/LT üzerinde LTA için.
  - ATSv3 (EN 319 122-1, ats-hash-index) bilinçli olarak atlandı — v2
    ETSI-compliant ve karmaşıklığı düşük.

- **ASiC container** — `src/asic.ts`:
  - `createAsic(opts)` — discriminated union: `asic-s` (tek veri + tek sig)
    veya `asic-e` (multi-dosya + multi-sig + ops. manifest).
  - `readAsic(bytes)` — mimetype tespiti + dataFiles/signatures/manifests
    sınıflandırması.
  - EN 319 162-1 §A.1 uyumlu: mimetype FIRST entry + STORED, XAdES
    `signatures.xml` / CAdES `signature.p7s` naming + E için `NNN` indeks.
  - `fflate` (MIT, ~8kb, tree-shakable) tek dep.
  - Subpath export: `tr-esign/asic`.

- **Test altyapısı**:
  - `reference/gen-test-ca.sh` — openssl ile 3-katmanlı test CA
    (root → intermediate → leaf), leaf'ta KeyUsage digitalSignature +
    nonRepudiation + AIA + CDP placeholder. PFX export `test-chain.p12`.
  - `test-chain-*.pem` trust anchor + okunabilir chain.

### Değişti

- `cades-upgrade.ts` — `addArchiveTimeStamp()` SignerInfo alanıı `si.toSchema()`
  inner node'larından iterate ederek alıyor (çoklu parse/re-serialize sonrası
  `si.sid` tip kararlılığı için). [1] IMPLICIT unsignedAttrs skip.
- `reference/driver/Ma3Ref.java` — chain PFX yükleme kodu halâ içeride,
  CAdES fixture üretim denemesi meta.json'da loglanıyor.
- `.gitignore` — `reference/fixtures/*.pem` eklendi.

### Bilinen sınırlamalar

- **MA3 CAdES cross-verify ertelendi (v0.5+)**: MA3 `addSigner()` CAdES-BES
  için bile online revocation zorunluyor (NPE at `CertificateStatusInfo.
  getCertificate()`). Test CA placeholder URL'lere ulaşamadığı için fixture
  üretilemedi. `cades-cross-verify.test.ts` fixture varsa doğrular, yoksa
  skip. Çözüm: yerel openssl ocsp responder veya gerçek TR mali mühür PFX.
- CAdES-LTA'da ATSv3 (ats-hash-index) yok; v2 yeterli. ATSv3 v0.5+'a.
- ASiC-E XAdES manifest üretimi otomatik değil — kullanıcı ayrı yazıp
  opts.manifest ile verir (XAdES için genelde gereksiz, CAdES için zorunlu).

## [0.3.0] — CAdES (CMS/PKCS#7)

XAdES'le paralel ikinci imza formatı: CMS SignedData üzerinde ASN.1 DER
binary imza. TR'de e-reçete, ikili doküman ve detached özet imza
senaryolarında kullanılır.

### Eklendi

- **`src/cades-sign.ts`** — `cadesSign(opts)`. Attached (içerik imza içinde)
  ve detached (harici veri) mod. Standart signedAttrs: contentType +
  messageDigest + signingCertificateV2 (RFC 5035) + signingTime. Opsiyonel:
  signaturePolicyIdentifier (EPES), commitmentTypeIndication.
- **`src/cades-verify.ts`** — `cadesVerify(bytes, opts?)`. CMS SignedData +
  pkijs verify. VerifyResult tipi XAdES ile aynı (certToSignerInfo
  verify.ts'ten ortak export). Seviye tespiti signed/unsigned attribute
  varlığından: signaturePolicy→EPES, signatureTimeStamp→T,
  certValues/revocationValues→LT, archiveTimeStampV2/V3→LTA.
- **`src/cades-upgrade.ts`** — `cadesUpgrade({bytes, to:'T', tsa?})`.
  ETSI TS 101 733 §6.1.1 signature-time-stamp: SignerInfo.signature üzerinde
  RFC 3161 timestamp, unsignedAttrs'e eklenir. LT/LTA v0.3.x adayı.
- **`src/cades-attributes.ts`** — 9 pkijs.Attribute builder (contentType,
  messageDigest, signingTime UTCTime/GeneralizedTime, signingCertificateV2
  ESSCertIDv2 + issuerSerial, signaturePolicyIdentifier, commitmentTypeIndication,
  signatureTimeStamp).
- **`src/cades-constants.ts`** — RFC 5652 + ETSI TS 101 733 OID'leri +
  HASH_OID mapping (NIST alg OID).
- **Subpath exports**: `tr-esign/cades-sign`, `tr-esign/cades-verify`,
  `tr-esign/cades-upgrade`.

### Değişti

- `src/pfx.ts` — pkijs crypto engine'i `@peculiar/webcrypto`'dan Node 22 global
  `crypto.subtle`'a taşındı. CryptoKey'ler artık `crypto.ts` ile `pkijs`
  arasında uyumlu. `@peculiar/webcrypto` deps arasında kalmaya devam ediyor ama
  kullanılmıyor (sonraki release'te kaldırılabilir).
- `src/verify.ts` — `certToSignerInfo(cert: pkijs.Certificate): SignerInfo`
  export edildi (verify.ts + cades-verify.ts ortak kullanımı için).
- `src/sign.ts` — `resolveSigner` ve `SignerInput` tipi CAdES tarafından da
  kullanıldığı için genel input parametresi kabul edecek şekilde imza sadeleşti.
- `reference/fixtures/test.p12` — KeyUsage=digitalSignature,nonRepudiation
  extension'ıyla regen edildi (MA3 CAdES first gate'i için gerekli).

### Bilinen sınırlamalar

- **MA3 CAdES interop testi fixture bekliyor**: MA3 `addSigner` default path
  validation yapar ve self-signed test cert'imizi kabul etmez. Gerçek TR
  mali mühür (Kamu SM NES zinciriyle imzalı) PFX sağlandığında
  `test/cades-cross-verify.test.ts` otomatik aktif olur.
- CAdES-LT / CAdES-LTA v0.3.0 kapsamında değil.
- SignerLocation, SignerAttr attribute'ları BES için zorunlu değil — eklenmedi.

## [0.2.0] — MA3 interop + XAdES gap closure

### Eklendi

- **`placement: "ubl-ma3-compat"`** (`src/sign.ts`) — MA3 (TÜBİTAK BİLGEM)
  doğrulayıcısı ile tam yapısal interop. Input XML base64 olarak `ds:Object`'te,
  `ds:Reference` `URI="#<objectId>"` (enveloped-signature transform yok) — MA3'ün
  kendi enveloped çıktısıyla birebir. MA3 verifier'ı 'Temel doğrulama başarılı'
  verir (tek kalan: cert chain trust self-signed test cert için; gerçek mali mühür
  ile çözülür).
- **External URI resolver** (`src/verify.ts`) — `verify(xml, opts?)`. `VerifyOptions.resolver?`
  callback ile detached imzalar ve external URI referansları çözün. MA3 detached
  fixture'ı artık file-system resolver ile valid.
- **`counterSign(opts)`** (`src/counter-sign.ts`) — XAdES CounterSignature. Mevcut
  `ds:Signature`'ın `ds:SignatureValue`'suna yeni imza atar
  (`Type="...#CountersignedSignature"`), parent'ın
  `xades:UnsignedSignatureProperties/xades:CounterSignature` altına yerleştirilir.
- **Recursive counter-sig verify** (`src/verify.ts`) — `VerifyResult.counterSignatures?:
  SignerInfo[]` ile geçerli counter-sig'lerin signer bilgisi.
- **Paralel (multi) imza** (`src/verify.ts`) — `ubl-ma3-compat` iki kez çağrılınca
  bağımsız paralel imzalar; verify `allSignatures?: PerSignatureResult[]` ile her
  top-level sig'i ayrı ayrı raporlar (primary hala ilk sig).
- XMLDSig şema çocuk sırası düzeltmesi: `ds:Signature` artık
  `SignedInfo, SignatureValue, KeyInfo, Object*` sırasında.

### Değişti

- `verify(xml)` → `verify(xml, opts?)` (eklemeli değişiklik; eski çağrılar çalışır).
- `sign.ts`'ten `resolveSigner`, `buildKeyInfo`, `SignerInput` tipi; `upgrade.ts`'ten
  `ensureUnsignedSignatureProperties` export edildi — yeni `counter-sign.ts` ile
  duplicate logic engellendi.

### Kaldırılan bilinen sınırlama

- MA3 interop'ta UBL enveloped sorunu (v0.1 'Temel doğrulama başarısız') çözüldü.
- Detached imza doğrulama (v0.1'de yoktu) artık kullanıcı resolver'ıyla çalışıyor.

## [0.1.0] — Unreleased (v0.1.0 taslak)

İlk sürüm. Türkiye profili XAdES kütüphanesi — clean-room, ETSI +
kamuya açık TR dokümanlardan.

### Eklendi

- **Seviyeler:** XAdES-BES, XAdES-EPES, XAdES-T, XAdES-LT, XAdES-LTA.
- **Girdi şekilleri:** enveloped (UBL-TR `ext:ExtensionContent` yerleştirme,
  kök elemente ekleme) / enveloping (`ds:Object` içinde base64) / detached
  (external URI reference, sign tarafı).
- **Signer:** PFX (PKCS#12, pkijs tabanlı) ve pkcs8+X.509 DER.
- **Algoritmalar:** RSA-PKCS1-v1_5 ve ECDSA × SHA-256/384/512; c14n10 +
  exc-c14n (with/without comments).
- **TR profili:** P2/P3/P4 v1 policy OID'leri (runtime'da MA3 obfuscation
  çözülüp doğrulandı) + Elektronik İmza Kullanım Profilleri Rehberi PDF
  SHA-256 digest'i (`ff39bd29…08117a`).
- **Yardımcı modüller:** `pfx`, `crypto`, `c14n`, `ids`, `policy`, `tsp`
  (RFC 3161), `ocsp` (RFC 6960), `crl` (RFC 5280), `chain`
  (pkijs ChainValidationEngine) + `loadKamuSmRoots()` runtime fetch.
- **API:** tek `sign()`, tek `verify()`, tek `upgrade()` fonksiyonu (to:
  T/LT/LTA discriminated union).
- **Canonicalization interop:** xmldsigjs'in subset-topmost inheritance
  eksikliği Apache Santuario / MA3 davranışıyla hizalayan
  `withInheritedNamespaces()` eklendi. MA3 fixture digest'leri byte-byte
  eşleşmesi doğrulandı.
- **Interop:** MA3 enveloping + enveloped-embedded fixture'ları `verify()`'da
  valid geçiyor. Ters yön (tr-esign → MA3) enveloping için geçiyor (chain
  trust hariç). Enveloped UBL için yapısal konvansiyon farkı (MA3 fragment-id
  kullanır) v0.2 kapsamında.
- **Test:** 32 offline test (lint + typecheck clean). Opt-in live TSA
  testleri FreeTSA ile çalışıyor (BES→T + LT→LTA round-trip verify=✅).
- **Örnek:** `examples/sign-efatura.ts` — UBL 2.1 + TR 1.2 TEMELFATURA
  iskeleti imzala + doğrula.
- **Referans:** `reference/driver/Ma3Ref.java` (MA3 ile fixture üret, TR
  policy OID'leri runtime-dump) + `reference/driver/Ma3Verify.java`
  (tr-esign çıktılarını MA3 ile doğrula).

### Kapsam dışı (v0.1 bilinçli kararlar)

- CAdES, PAdES, ASiC — yalnız XAdES.
- PKCS#11 / akıllı kart — yumuşak anahtar; ayrı paket `tr-esign-pkcs11`
  planlı.
- Turkcell/Vodafone/Avea Mobil İmza (MSS) — operatör hesabı gerektirir, v1.x.
- Browser — Node 20+ only.
- CLI — library-only.
- verify(): chain validation default KAPALI (kullanıcı `validateChain()` ile
  açık trust bundle üstünde yapar).
- detached verify: external URI çözücü yok (bytes dışarıdan gelirse
  parseable).
- XAdES-X Type1/Type2 Complete*Refs (legacy) — modern LT'de CertificateValues
  + RevocationValues yeterli.
- C14N 1.1 — xmldsigjs desteklemez, TR profili gerektirmez.

### Bilinen sınırlamalar

- UBL enveloped imzamız (URI="" + enveloped-signature + exc-c14n) MA3
  doğrulayıcısı tarafından "Temel doğrulama başarısız" olarak işaretleniyor;
  MA3 fragment-id konvansiyonu kullanır. v0.2'de `ubl-ma3-compat` placement
  modu adayı.
- Self-signed test cert Kamu SM bundle'ında olmadığı için MA3 her zaman
  "İmzacı sertifikası doğrulanamadı" ile reddedecek — mali mühür
  entegrasyonu için gerçek TR cert gerekir.
- xmldom ↔ lib.dom TypeScript tipi uyumsuzluğu 2 yerde `any` cast gerektirdi
  (contained).

### Meta

- 15 src dosyası, ~1850 satır, barrel yok, flat yapı.
- 12 subpath export (tr-esign/sign, /verify, /upgrade, /pfx, /crypto, …).
- `@typescript/native-preview` (tsgo), `oxlint`, `tsx` dev stack.
- Dependencies: `xmldsigjs`, `pkijs`, `asn1js`, `@peculiar/webcrypto`,
  `@xmldom/xmldom`, `xpath`, `pvutils`.
