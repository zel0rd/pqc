# Crypto CI Lab

Simple GitHub Actions lab for detecting weak cryptographic API usage.

## Local test

```bash
python3 -m pip install -r requirements.txt
python3 tools/crypto_scan.py --fail-on high
```

Expected: the scan fails because `src/vulnerable_crypto.c` and `src/vulnerable_crypto.java` intentionally contain MD5, SHA-1, DES/ECB, RSA-1024, RSA, and ECC examples.

## GitHub Actions test

1. Push this repository to GitHub.
2. Open the Actions tab.
3. Select `Crypto Policy Scan`.
4. Confirm that the workflow fails.
5. Download the `crypto-scan-report` artifact.
