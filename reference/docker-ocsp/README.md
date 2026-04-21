# docker-ocsp/

MA3 CAdES / PAdES fixture üretimi için yerel revocation altyapısı.

## Amaç

- `openssl ocsp` ile **intermediate CA** adına OCSP responder
- `python -m http.server` ile **CRL dağıtımı**
- `reference/gen-test-ca.sh` ile üretilen test zincirinin AIA / CDP URL'leri
  varsayılan olarak bu host port'larına işaret eder:
  - OCSP: `http://127.0.0.1:18080/ocsp`
  - Intermediate CRL: `http://127.0.0.1:18081/int.crl`
  - Root CRL: `http://127.0.0.1:18081/root.crl`

## Kullanım

```bash
# 1) Test zincirini ve responder materyallerini üret
bash reference/gen-test-ca.sh

# 2) Yerel OCSP + CRL servislerini kaldır
cd reference/docker-ocsp
docker compose up -d

# 3) Sağlık kontrolü
curl -I http://127.0.0.1:18081/int.crl
curl -I http://127.0.0.1:18081/root.crl
```

## Üretilen dosyalar

`reference/docker-ocsp/ca/` içine yazılır (git-ignore):

- `root.crt`, `root.key`
- `int.crt`, `int.key`
- `responder.crt`, `responder.key`
- `root.index.txt`, `int.index.txt`
- `root.cnf`, `int.cnf`
- `www/root.crl`, `www/int.crl`

## Notlar

- OCSP responder leaf + responder sertifikalarının durumunu `int.index.txt`
  üzerinden cevaplar.
- Intermediate sertifika için root CRL URL'si gömülüdür; bu yüzden iki CRL
  dosyası servis edilir.
- Bu klasör yalnız MA3 interop fixture üretimi içindir; tr-esign runtime
  kütüphanesinin parçası değildir.
