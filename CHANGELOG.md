# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). SemVer.

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
  valid geçiyor. Ters yön (tr-xades → MA3) enveloping için geçiyor (chain
  trust hariç). Enveloped UBL için yapısal konvansiyon farkı (MA3 fragment-id
  kullanır) v0.2 kapsamında. Detaylar: `docs/04-interop-report.md`.
- **Test:** 32 offline test (lint + typecheck clean). Opt-in live TSA
  testleri FreeTSA ile çalışıyor (BES→T + LT→LTA round-trip verify=✅).
- **Örnek:** `examples/sign-efatura.ts` — UBL 2.1 + TR 1.2 TEMELFATURA
  iskeleti imzala + doğrula.
- **Referans:** `reference/driver/Ma3Ref.java` (MA3 ile fixture üret, TR
  policy OID'leri runtime-dump) + `reference/driver/Ma3Verify.java`
  (tr-xades çıktılarını MA3 ile doğrula).

### Kapsam dışı (v0.1 bilinçli kararlar)

- CAdES, PAdES, ASiC — yalnız XAdES.
- PKCS#11 / akıllı kart — yumuşak anahtar; ayrı paket `tr-xades-pkcs11`
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
- 12 subpath export (tr-xades/sign, /verify, /upgrade, /pfx, /crypto, …).
- `@typescript/native-preview` (tsgo), `oxlint`, `tsx` dev stack.
- Dependencies: `xmldsigjs`, `pkijs`, `asn1js`, `@peculiar/webcrypto`,
  `@xmldom/xmldom`, `xpath`, `pvutils`.
