#!/usr/bin/env bash
set -euo pipefail

mkdir -p results certs

echo "[1] Compile vulnerable C examples"
for f in vulnerable-c/*.c; do
    name=$(basename "$f" .c)
    gcc "$f" -o "results/$name" -lcrypto 2>/dev/null || true
done

echo
echo "[2] Run Python C crypto scanner"
python3 scripts/scan_crypto_c.py .

echo
echo "[3] Run Semgrep rules"
if command -v semgrep >/dev/null 2>&1; then
    semgrep --config rules/c-crypto-rules.yml vulnerable-c || true
else
    echo "Semgrep not installed. Install it with: python3 -m pip install --user semgrep"
fi

echo
echo "[5] Check OpenSSL PQC support"
bash scripts/openssl_pqc_check.sh

echo
echo "[6] Generate and inspect certificates"
openssl req -x509 -newkey rsa:2048 \
  -keyout certs/rsa_key.pem \
  -out certs/rsa_cert.pem \
  -days 365 -nodes \
  -subj "/CN=RSA Test Cert" >/dev/null 2>&1 || true

openssl ecparam -name prime256v1 -genkey -noout -out certs/ec_p256_key.pem || true

openssl req -x509 -new \
  -key certs/ec_p256_key.pem \
  -out certs/ec_p256_cert.pem \
  -days 365 \
  -subj "/CN=ECDSA P256 Test Cert" >/dev/null 2>&1 || true

bash scripts/cert_algo_extract.sh

echo
echo "[+] Lab completed."
echo "[+] Check results/ directory."
