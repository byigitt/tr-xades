# CAdES-LTA ATSv3 research notes (v0.7 / Faz 3.1)

Amaç: `archive-time-stamp-v3` + `ATSHashIndex` yapısını netleştirip
`src/cades-upgrade.ts` için küçük, doğru implementasyon planı çıkarmak.

## OID'ler

- `archiveTimeStampV3` = `0.4.0.1733.2.4`
- `ATSHashIndex`      = `0.4.0.1733.2.5`

Repo durumu:
- `src/cades-constants.ts` içinde `archiveTimeStampV3` zaten var.
- `ATSHashIndex` OID sabiti henüz **yok** → Faz 3.2'de eklenecek.

## ATSHashIndex ASN.1 yapısı

MA3 `EATSHashIndex` / `AtsHashIndexAttr` gözlemi:

```asn1
ATSHashIndex ::= SEQUENCE {
  hashIndAlgorithm     AlgorithmIdentifier DEFAULT id-sha256,
  certificatesHashIndex  SEQUENCE OF OCTET STRING,
  crlsHashIndex          SEQUENCE OF OCTET STRING,
  unsignedAttrsHashIndex SEQUENCE OF OCTET STRING
}
```

Pratik notlar:
- `hashIndAlgorithm` opsiyonel; SHA-256 ise encode edilmeyebilir.
- Her dizi elemanı **tekil DER nesnesinin hash'i**:
  - cert için `DER(CertificateChoices)`
  - CRL için `DER(RevocationInfoChoice / CertificateList)`
  - unsigned attr için `DER(Attribute)`

## ATSHashIndex hangi unsigned attr'ları kapsar?

MA3 `ATSHashIndexAttrChecker` ve `TimeStampMessageDigestChecker` gözlemi:

1. `unsignedAttrsHashIndex` içine normal unsigned attrs girer.
2. `id-countersignature` attr'ları **dahil edilir**.
3. `archiveTimeStampV3` attr'larının **kendisi** genel döngüde hariç tutulur.
4. Ama signer'daki daha eski `archiveTimeStampV3` attr'ları, sadece
   **mevcut timestamp genTime'ından önce** ise ayrıca kapsama alınır.
5. Sonuç: current ATSv3 attr kendini hash'lemez; önceki ATSv3 attr'ları zincir
   sürekliliği için kapsama döner.

Bu, bizim implementasyonda şu anki v2 yolundaki "prior ATS hariç unsigned attrs"
 mantığını v3 için biraz genişletmemiz gerektiğini gösteriyor.

## Message imprint farkı: V2 vs V3

MA3 `TimeStampMessageDigestChecker` içinde ESAv3 için ekstra `ATSHashIndex`
 encode akışı var:

- normal archive-time-stamp concat girdisi korunuyor
- buna ek olarak `DER(ATSHashIndex)` de imprint input'una katılıyor

Yani pratik plan:

```text
imprint-v3 = hash(
  v2-imprint-input
  || DER(ATSHashIndex)
)
```

Buradaki `v2-imprint-input` halen şu parçaları kapsıyor:
- encapsulated content info / detached content eşdeğeri
- certificates
- crls
- signerInfo'nun unsignedAttrs HARİÇ alanları
- unsignedAttrs (archive timestamp attr'ları hariç / zaman filtresiyle)

## MA3 ürün davranışı

- MA3 config/parameters içinde `isUseCAdESATSv2()` flag'i var.
- Bu, runtime'da v2/v3 seçiminin konfigüre edilebilir olduğunu gösteriyor.
- Bizde de en sade yol:
  - default: `variant: "v3"`
  - override: `{ variant: "v2" }`

## Faz 3.2 için minimal implementasyon planı

1. `src/cades-constants.ts`
   - `atsHashIndex: "0.4.0.1733.2.5"`

2. `src/cades-attributes.ts`
   - `buildAtsHashIndexAttr({ digestAlgorithm?, certs, crls, unsignedAttrs })`
   - çıktı: `pkijs.Attribute` (`type=atsHashIndex`, value=ASN.1 SEQUENCE)

3. `src/cades-upgrade.ts`
   - `to:"LTA"` opts genişlet:
     - `variant?: "v2" | "v3"`
   - default `v3`
   - v3 akışı:
     1. `ATSHashIndex` value üret
     2. unsignedAttrs'a `ATSHashIndex` ekle
     3. imprint input = eski archive concat + `DER(ATSHashIndex value)`
     4. TSA token al
     5. `archiveTimeStampV3` unsigned attr ekle

4. verify seviyesi
   - `cades-verify.ts` şimdiden `archiveTimeStampV3` görürse `LTA` sayıyor;
     burada ek değişiklik gerekmeyebilir.

## Risk / dikkat

- `pkijs` ile custom ASN.1 SEQUENCE üretirken `hashIndAlgorithm` default SHA-256
  ise encode etmeme davranışı tercih edilmeli; ama ilk sürümde encode edilmesi
  genelde sorun çıkarmaz. Yine de MA3 ile daha yakın uyum için SHA-256'da omit
  etmek daha iyi.
- `unsignedAttrsHashIndex` için attr sırası mevcut signer unsignedAttrs sırasını
  bozmadan korunmalı.
- v3 attr eklendikten sonra ikinci LTA upgrade çağrısında önceki v3 attr artık
  hash kapsamına dahil edilmeli (genTime filtresi mantığı).
