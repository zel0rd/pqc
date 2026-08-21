# Certificate-less KEX Migration & Fallback Lab

This lab intentionally removes certificates and authentication to focus only on key-exchange migration and fallback.
It is not TLS and not production security.

## Setup
```bash
cd kex_migration_fallback_lab
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

## Run all scenarios
```bash
./run_demo.sh
```

## Individual commands
```bash
python3 handshake_lab.py --client-offers x25519 --server-supports x25519
python3 handshake_lab.py --client-offers hybrid,toy-pqc,x25519 --server-supports hybrid,x25519
python3 handshake_lab.py --client-offers hybrid,toy-pqc,x25519 --server-supports x25519
python3 handshake_lab.py --client-offers hybrid,x25519 --server-supports hybrid,x25519 --max-bytes 500 --retry-classic-on-size
python3 handshake_lab.py --client-offers hybrid,x25519 --server-supports x25519 --require-pqc
python3 handshake_lab.py --client-offers hybrid,x25519 --server-supports hybrid,x25519 --downgrade-strip --require-pqc
```
