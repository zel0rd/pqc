#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="${HOME}/oqs-cert-lab"
mkdir -p "${LAB_DIR}"/{certs,keys,csr,der,reports}
cd "${LAB_DIR}"

echo "[1] Check OpenSSL providers"
openssl list -providers -provider default -provider oqsprovider || true

echo
echo "[2] Check OQS signature algorithms"
openssl list -signature-algorithms \
  -provider default \
  -provider oqsprovider | grep -E "mldsa|p256_mldsa|ecdsa" || true

echo
echo "[3] Generate classical ECDSA P-256 key"
openssl ecparam \
  -name prime256v1 \
  -genkey \
  -noout \
  -out keys/ecdsa_p256.key

echo "[4] Generate ECDSA CSR"
openssl req -new \
  -key keys/ecdsa_p256.key \
  -out csr/ecdsa_p256.csr \
  -subj "/C=KR/O=Hansung University/OU=Crypto Lab/CN=ecdsa-p256.local"

echo "[5] Generate self-signed ECDSA certificate"
openssl req -x509 \
  -key keys/ecdsa_p256.key \
  -in csr/ecdsa_p256.csr \
  -out certs/ecdsa_p256.crt \
  -days 365 \
  -sha256

echo
echo "[6] Generate PQC-only ML-DSA-44 key"
openssl genpkey \
  -algorithm mldsa44 \
  -out keys/mldsa44.key \
  -provider default \
  -provider oqsprovider

echo "[7] Generate ML-DSA-44 CSR"
openssl req -new \
  -key keys/mldsa44.key \
  -out csr/mldsa44.csr \
  -subj "/C=KR/O=Hansung University/OU=Crypto Lab/CN=mldsa44.local" \
  -provider default \
  -provider oqsprovider

echo "[8] Generate self-signed ML-DSA-44 certificate"
openssl req -x509 \
  -key keys/mldsa44.key \
  -in csr/mldsa44.csr \
  -out certs/mldsa44.crt \
  -days 365 \
  -provider default \
  -provider oqsprovider

echo
echo "[9] Generate hybrid p256_mldsa44 key"
openssl genpkey \
  -algorithm p256_mldsa44 \
  -out keys/p256_mldsa44.key \
  -provider default \
  -provider oqsprovider

echo "[10] Generate hybrid p256_mldsa44 CSR"
openssl req -new \
  -key keys/p256_mldsa44.key \
  -out csr/p256_mldsa44.csr \
  -subj "/C=KR/O=Hansung University/OU=Crypto Lab/CN=p256-mldsa44.local" \
  -provider default \
  -provider oqsprovider

echo "[11] Generate self-signed hybrid p256_mldsa44 certificate"
openssl req -x509 \
  -key keys/p256_mldsa44.key \
  -in csr/p256_mldsa44.csr \
  -out certs/p256_mldsa44.crt \
  -days 365 \
  -provider default \
  -provider oqsprovider

echo
echo "[12] Convert certificates to DER"
openssl x509 -in certs/ecdsa_p256.crt \
  -outform DER \
  -out der/ecdsa_p256.der

openssl x509 -in certs/mldsa44.crt \
  -outform DER \
  -out der/mldsa44.der \
  -provider default \
  -provider oqsprovider

openssl x509 -in certs/p256_mldsa44.crt \
  -outform DER \
  -out der/p256_mldsa44.der \
  -provider default \
  -provider oqsprovider

echo
echo "[13] Generate size report"
{
  echo "=== PEM certificate size ==="
  ls -lh certs/*.crt

  echo
  echo "=== DER certificate size ==="
  ls -lh der/*.der

  echo
  echo "=== Private key size ==="
  ls -lh keys/*.key

  echo
  echo "=== CSR size ==="
  ls -lh csr/*.csr

  echo
  echo "=== Exact byte size ==="
  wc -c certs/*.crt der/*.der keys/*.key csr/*.csr
} | tee reports/cert_size_report.txt

echo
echo "[14] Generate algorithm report"
{
  for cert in certs/*.crt; do
    echo "===================================================="
    echo "[CERT] $cert"
    echo "===================================================="
    openssl x509 \
      -in "$cert" \
      -text \
      -noout \
      -provider default \
      -provider oqsprovider | \
      grep -E "Signature Algorithm|Public Key Algorithm|Public-Key|ASN1 OID|Subject:|Issuer:"
    echo
  done
} | tee reports/cert_algorithm_report.txt

echo
echo "[15] Generate ASN.1 reports"

openssl asn1parse \
  -in certs/ecdsa_p256.crt \
  -i \
  -dump > reports/asn1_ecdsa_p256.txt

openssl asn1parse \
  -in certs/mldsa44.crt \
  -i \
  -dump > reports/asn1_mldsa44.txt

openssl asn1parse \
  -in certs/p256_mldsa44.crt \
  -i \
  -dump > reports/asn1_p256_mldsa44.txt

echo
echo "[16] Verify certificates"

openssl verify \
  -CAfile certs/ecdsa_p256.crt \
  certs/ecdsa_p256.crt

openssl verify \
  -provider default \
  -provider oqsprovider \
  -CAfile certs/mldsa44.crt \
  certs/mldsa44.crt

openssl verify \
  -provider default \
  -provider oqsprovider \
  -CAfile certs/p256_mldsa44.crt \
  certs/p256_mldsa44.crt

echo
echo "[DONE] Reports are stored in ${LAB_DIR}/reports"
