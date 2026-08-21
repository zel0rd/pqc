#!/usr/bin/env bash
set +e
python3 -m pip install cryptography >/dev/null 2>&1 || true

echo "\n[1] Legacy baseline: x25519 only"
python3 handshake_lab.py --client-offers x25519 --server-supports x25519

echo "\n[2] Migration: client/server prefer hybrid"
python3 handshake_lab.py --client-offers hybrid,toy-pqc,x25519 --server-supports hybrid,x25519

echo "\n[3] Compatibility fallback: server is legacy only"
python3 handshake_lab.py --client-offers hybrid,toy-pqc,x25519 --server-supports x25519

echo "\n[4] MTU/packet-size fallback: hybrid too large, retry classic"
python3 handshake_lab.py --client-offers hybrid,x25519 --server-supports hybrid,x25519 --max-bytes 500 --retry-classic-on-size

echo "\n[5] Secure policy: fallback blocked when PQC/hybrid is required"
python3 handshake_lab.py --client-offers hybrid,x25519 --server-supports x25519 --require-pqc

echo "\n[6] Downgrade attack demo: attacker strips PQC; policy detects it"
python3 handshake_lab.py --client-offers hybrid,x25519 --server-supports hybrid,x25519 --downgrade-strip --require-pqc
