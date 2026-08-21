#!/usr/bin/env bash
set -euo pipefail

mkdir -p results
OUT="results/openssl_pqc_check.txt"

{
    echo "=== OpenSSL Version ==="
    openssl version || true

    echo
    echo "=== OpenSSL Build Information ==="
    openssl version -a || true

    echo
    echo "=== Providers ==="
    openssl list -providers || true

    echo
    echo "=== KEM Algorithms ==="
    openssl list -kem-algorithms || true

    echo
    echo "=== Signature Algorithms ==="
    openssl list -signature-algorithms || true

    echo
    echo "=== PQC Keyword Search ==="
    openssl list -kem-algorithms 2>/dev/null | grep -Ei "ML-KEM|Kyber|X25519MLKEM|SecP256r1MLKEM" || true
    openssl list -signature-algorithms 2>/dev/null | grep -Ei "ML-DSA|Dilithium|SLH-DSA|SPHINCS" || true
} | tee "$OUT"
