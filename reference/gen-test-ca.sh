#!/usr/bin/env bash
# Test CA hiyerarşisi üretir: root → intermediate → leaf signer.
# Çıktı: reference/fixtures/test-chain.p12 (leaf + chain, şifre testpass)
#        reference/fixtures/test-chain-root.pem (trust anchor)
#        reference/docker-ocsp/ca/* (OCSP responder + CRL server materyali)
#
# Leaf'ta KeyUsage=digitalSignature+nonRepudiation, AIA (OCSP) + CDP.
# MA3 CAdES/PAdES path validation'ı geçmek için yerel docker-ocsp ile uyumlu.
#
# Kullanım:
#   cd reference && bash gen-test-ca.sh
#   cd docker-ocsp && docker compose up -d

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURES_DIR="$ROOT_DIR/fixtures"
DOCKER_OCSP_DIR="$ROOT_DIR/docker-ocsp/ca"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS="testpass"
OCSP_URL="${TR_ESIGN_TEST_OCSP_URL:-http://127.0.0.1:18080/ocsp}"
INT_CRL_URL="${TR_ESIGN_TEST_INT_CRL_URL:-http://127.0.0.1:18081/int.crl}"
ROOT_CRL_URL="${TR_ESIGN_TEST_ROOT_CRL_URL:-http://127.0.0.1:18081/root.crl}"

mkdir -p "$FIXTURES_DIR" "$DOCKER_OCSP_DIR/www" "$DOCKER_OCSP_DIR/newcerts"
cd "$FIXTURES_DIR"

# ---- Root CA (self-signed) ----
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
	-subj "/C=TR/O=tr-esign test/CN=tr-esign Test Root CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-addext "subjectKeyIdentifier=hash" \
	-keyout "$TMP/root.key" -out "$TMP/root.crt" 2>/dev/null

# ---- Intermediate CA (root ile imzalı) ----
openssl req -newkey rsa:2048 -sha256 -nodes \
	-subj "/C=TR/O=tr-esign test/CN=tr-esign Test Intermediate CA" \
	-keyout "$TMP/int.key" -out "$TMP/int.csr" 2>/dev/null

cat > "$TMP/int.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
crlDistributionPoints=URI:$ROOT_CRL_URL
EOF

openssl x509 -req -in "$TMP/int.csr" -CA "$TMP/root.crt" -CAkey "$TMP/root.key" \
	-CAcreateserial -sha256 -days 1825 -extfile "$TMP/int.ext" \
	-out "$TMP/int.crt" 2>/dev/null

# ---- Leaf signer (intermediate ile imzalı) ----
openssl req -newkey rsa:2048 -sha256 -nodes \
	-subj "/C=TR/O=tr-esign test/CN=Test Signer" \
	-keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" 2>/dev/null

cat > "$TMP/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=clientAuth,emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
authorityInfoAccess=OCSP;URI:$OCSP_URL
crlDistributionPoints=URI:$INT_CRL_URL
EOF

openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/int.crt" -CAkey "$TMP/int.key" \
	-CAcreateserial -sha256 -days 1095 -extfile "$TMP/leaf.ext" \
	-out "$TMP/leaf.crt" 2>/dev/null

# ---- OCSP responder cert (intermediate ile imzalı) ----
openssl req -newkey rsa:2048 -sha256 -nodes \
	-subj "/C=TR/O=tr-esign test/CN=tr-esign Test OCSP Responder" \
	-keyout "$TMP/responder.key" -out "$TMP/responder.csr" 2>/dev/null

cat > "$TMP/responder.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=OCSPSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
crlDistributionPoints=URI:$INT_CRL_URL
EOF

openssl x509 -req -in "$TMP/responder.csr" -CA "$TMP/int.crt" -CAkey "$TMP/int.key" \
	-CAcreateserial -sha256 -days 1095 -extfile "$TMP/responder.ext" \
	-out "$TMP/responder.crt" 2>/dev/null

# ---- PFX paketi (leaf + chain, şifre testpass) ----
cat "$TMP/int.crt" "$TMP/root.crt" > "$TMP/chain.pem"

openssl pkcs12 -export -name "test-signer" \
	-in "$TMP/leaf.crt" -inkey "$TMP/leaf.key" \
	-certfile "$TMP/chain.pem" \
	-password "pass:$PASS" -out test-chain.p12 2>/dev/null

# Trust anchor (root) + okunabilir chain
cp "$TMP/root.crt" test-chain-root.pem
cat "$TMP/leaf.crt" "$TMP/int.crt" "$TMP/root.crt" > test-chain-full.pem

# ---- Docker OCSP / CRL materyali ----
cp "$TMP/root.crt" "$DOCKER_OCSP_DIR/root.crt"
cp "$TMP/root.key" "$DOCKER_OCSP_DIR/root.key"
cp "$TMP/int.crt" "$DOCKER_OCSP_DIR/int.crt"
cp "$TMP/int.key" "$DOCKER_OCSP_DIR/int.key"
cp "$TMP/leaf.crt" "$DOCKER_OCSP_DIR/leaf.crt"
cp "$TMP/responder.crt" "$DOCKER_OCSP_DIR/responder.crt"
cp "$TMP/responder.key" "$DOCKER_OCSP_DIR/responder.key"

printf '1000\n' > "$DOCKER_OCSP_DIR/root.serial"
printf '1000\n' > "$DOCKER_OCSP_DIR/int.serial"
printf '1000\n' > "$DOCKER_OCSP_DIR/root.crlnumber"
printf '1000\n' > "$DOCKER_OCSP_DIR/int.crlnumber"
printf 'unique_subject = no\n' > "$DOCKER_OCSP_DIR/root.index.txt.attr"
printf 'unique_subject = no\n' > "$DOCKER_OCSP_DIR/int.index.txt.attr"

emit_index_line() {
	python3 - "$1" <<'PY'
import datetime, subprocess, sys
cert = sys.argv[1]
enddate = subprocess.check_output(["openssl", "x509", "-in", cert, "-noout", "-enddate"], text=True).strip().split("=", 1)[1]
serial = subprocess.check_output(["openssl", "x509", "-in", cert, "-noout", "-serial"], text=True).strip().split("=", 1)[1]
subject = subprocess.check_output(["openssl", "x509", "-in", cert, "-noout", "-subject", "-nameopt", "RFC2253"], text=True).strip().split("=", 1)[1]
dt = datetime.datetime.strptime(enddate, "%b %d %H:%M:%S %Y %Z")
print(f"V\t{dt.strftime('%y%m%d%H%M%SZ')}\t\t{serial}\tunknown\t{subject}")
PY
}

emit_index_line "$TMP/int.crt" > "$DOCKER_OCSP_DIR/root.index.txt"
{
	emit_index_line "$TMP/leaf.crt"
	emit_index_line "$TMP/responder.crt"
} > "$DOCKER_OCSP_DIR/int.index.txt"

cat > "$DOCKER_OCSP_DIR/root.cnf" <<EOF
[ ca ]
default_ca = ca_default

[ ca_default ]
database = $DOCKER_OCSP_DIR/root.index.txt
serial = $DOCKER_OCSP_DIR/root.serial
crlnumber = $DOCKER_OCSP_DIR/root.crlnumber
default_md = sha256
default_crl_days = 30
private_key = $DOCKER_OCSP_DIR/root.key
certificate = $DOCKER_OCSP_DIR/root.crt
new_certs_dir = $DOCKER_OCSP_DIR/newcerts
policy = policy_any
x509_extensions = usr_cert
copy_extensions = copy

[ policy_any ]
commonName = supplied
organizationName = optional
countryName = optional
stateOrProvinceName = optional
organizationalUnitName = optional
emailAddress = optional

[ usr_cert ]
basicConstraints = CA:FALSE
EOF

cat > "$DOCKER_OCSP_DIR/int.cnf" <<EOF
[ ca ]
default_ca = ca_default

[ ca_default ]
database = $DOCKER_OCSP_DIR/int.index.txt
serial = $DOCKER_OCSP_DIR/int.serial
crlnumber = $DOCKER_OCSP_DIR/int.crlnumber
default_md = sha256
default_crl_days = 30
private_key = $DOCKER_OCSP_DIR/int.key
certificate = $DOCKER_OCSP_DIR/int.crt
new_certs_dir = $DOCKER_OCSP_DIR/newcerts
policy = policy_any
x509_extensions = usr_cert
copy_extensions = copy

[ policy_any ]
commonName = supplied
organizationName = optional
countryName = optional
stateOrProvinceName = optional
organizationalUnitName = optional
emailAddress = optional

[ usr_cert ]
basicConstraints = CA:FALSE
EOF

openssl ca -config "$DOCKER_OCSP_DIR/root.cnf" -gencrl -out "$DOCKER_OCSP_DIR/www/root.crl" -batch 2>/dev/null
openssl ca -config "$DOCKER_OCSP_DIR/int.cnf" -gencrl -out "$DOCKER_OCSP_DIR/www/int.crl" -batch 2>/dev/null

echo "done:"
echo "  reference/fixtures/test-chain.p12        (leaf+chain, şifre $PASS)"
echo "  reference/fixtures/test-chain-root.pem   (trust anchor)"
echo "  reference/fixtures/test-chain-full.pem   (okunabilir leaf→int→root)"
echo "  reference/docker-ocsp/ca/*               (OCSP responder + CRL materyali)"
echo ""
echo "AIA / CDP:"
echo "  leaf OCSP  = $OCSP_URL"
echo "  leaf CRL   = $INT_CRL_URL"
echo "  int CRL    = $ROOT_CRL_URL"
echo ""
echo "docker up:"
echo "  cd reference/docker-ocsp && docker compose up -d"
echo ""
openssl x509 -in "$TMP/leaf.crt" -noout -subject -issuer
