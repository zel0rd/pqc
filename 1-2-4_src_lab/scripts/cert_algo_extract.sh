#!/usr/bin/env bash
set -euo pipefail

mkdir -p results
OUT="results/cert_algorithms.txt"
: > "$OUT"

for cert in certs/*.pem; do
    if openssl x509 -in "$cert" -noout >/dev/null 2>&1; then
        echo "=== $cert ===" | tee -a "$OUT"

        echo "[Signature Algorithm]" | tee -a "$OUT"
        openssl x509 -in "$cert" -noout -text \
            | grep -m 1 "Signature Algorithm" \
            | sed 's/^ *//' | tee -a "$OUT"

        echo "[Public Key Algorithm]" | tee -a "$OUT"
        openssl x509 -in "$cert" -noout -text \
            | grep -m 1 "Public Key Algorithm" \
            | sed 's/^ *//' | tee -a "$OUT"

        echo "[Public Key Size / Curve]" | tee -a "$OUT"
        openssl x509 -in "$cert" -noout -text \
            | grep -E "Public-Key:|ASN1 OID:|NIST CURVE" \
            | sed 's/^ *//' | tee -a "$OUT"

        echo | tee -a "$OUT"
    fi
done
