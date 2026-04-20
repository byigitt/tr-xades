# tr-xades

Türkiye profili **XAdES** elektronik imza kütüphanesi (TypeScript / Node 20+).

> **Clean-room.** TÜBİTAK BİLGEM MA3 ile *kod düzeyinde hiçbir bağı yoktur*. Yalnızca aşağıdaki kamuya açık kaynaklara dayanır:
> - ETSI **TS 101 903 v1.4.2** (XAdES klasik) ve **EN 319 132-1/2** (yeni)
> - W3C **XML-DSig** Recommendation
> - GİB **UBL-TR / e-Fatura paketi** (kamuya açık şema ve örnekler)
> - RFC 3161 (TSP), RFC 6960 (OCSP), RFC 5280 (X.509), RFC 5652 (CMS)
> - MIT lisanslı [`@peculiar/xmldsigjs`](https://github.com/PeculiarVentures/xmldsigjs) ve `pkijs` ailesi

## Kapsam

XAdES-BES → XAdES-T → XAdES-LT → XAdES-LTA, TR profili.
İlk hedef: e-Fatura / e-Arşiv / UBL-TR imzalama, PFX/PEM ile yumuşak anahtar. PKCS#11 sonra.

## Hızlı bakış

```ts
import { signXAdES_BES } from "tr-xades";
import { readFileSync } from "node:fs";

const xml = readFileSync("invoice.xml", "utf8");
const pfx = readFileSync("mali-muhur.pfx");

const signed = await signXAdES_BES({
  xml,
  signer: { type: "pfx", pfx, password: process.env.PFX_PASS! },
  reference: { uri: "", transforms: ["enveloped", "c14n11"] },
  digestAlgorithm: "SHA-256",
});

console.log(signed); // imzalı XML string
```

## Lisans

MIT — bkz. [LICENSE](./LICENSE).

## Yasal Not

Bu proje TÜBİTAK BİLGEM MA3 API'sinin reverse engineering / decompile sonucu değildir.
Tamamen kamuya açık standart dokümanları ve MIT lisanslı bağımlılıklar üzerine inşa edilmiştir.
"Uyum Değerlendirme" gerektiren kullanım senaryolarında (resmi e-Fatura entegratörlüğü vb.)
kütüphanenin uygunluk denetimi kullanıcının sorumluluğundadır.
