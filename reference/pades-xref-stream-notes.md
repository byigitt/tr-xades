# PAdES xref-stream research notes (v0.7 / Faz 1.1)

Amaç: `pdf-lib` default kaydettiği modern PDF'lerde PAdES sign / DSS / visible
akışının neden koptuğunu netleştirmek.

## Bulgular

1. `pdf-lib` default `save()` çıktısı classic `trailer` + `xref` table değil,
   **cross-reference stream** yazar.
   - `startxref` doğrudan `N 0 obj << /Type /XRef /W [...] /Size ... >> stream`
     bloğuna gider.
   - Literal `trailer` string'i dosyada bulunmayabilir.

2. Bizde iki doğrudan kırık nokta var:
   - `src/pades-dss.ts` → `lastIndexOf("trailer")`
   - `src/pades-visible.ts` → `lastIndexOf("trailer")`

3. Asıl giriş noktası da kırık:
   - `src/pades-core.ts` → `@signpdf/placeholder-plain`
   - Bu paket içindeki `readPdf.js` + `readRefTable.js` classic xref table
     varsayar.
   - xref-stream PDF smoke sonucu:
     `Error: Expected xref at NaN but found other content.`

## Tasarım kararı

- Yeni `src/pades-xref.ts` helper eklenecek.
- `parseTrailer(pdf)` hem classic trailer hem de xref stream dictionary'den
  `{ root, info?, prev, size, startxref }` çıkaracak.
- Incremental append tarafında sade kalmak için **her zaman classic xref section**
  yazacağız. Yani input xref-stream olsa bile yeni revision classic `xref` +
  `trailer` + `/Prev <old-startxref>` ile eklenecek.
- Bu yol PDF parser yazmayı küçük tutar ve verifier'larla yüksek ihtimalle
  uyumludur.

## Sonuç

Faz 1 scope'u yalnız `pades-dss.ts` ve `pades-visible.ts` değil.
`pades-core.ts` placeholder yolu da aynı iterasyon serisinde çözülmeli; aksi
halde `pdf-lib` default üretilen PDF henüz imzalanamaz.
