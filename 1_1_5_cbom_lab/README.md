# CBOM Lab Package

This package contains a teaching-oriented lab for connecting CBOM theory to practice.

## Directory

- `java-demo/`: small Java service containing intentional crypto usages.
- `scanner/scan_java_crypto.py`: scans Java JCA/JCE API calls.
- `scanner/generate_cbom.py`: generates CycloneDX 1.7-style CBOM JSON.
- `scanner/risk_report.py`: generates a Markdown risk report from the CBOM.
- `certs/`: sample RSA-2048 self-signed TLS certificate for certificate-analysis exercises.
- `outputs/`: generated findings, CBOM, and report.

## Run

```bash
cd cbom_lab
python3 scanner/scan_java_crypto.py java-demo/src/main/java -o outputs/crypto_findings.json
python3 scanner/generate_cbom.py outputs/crypto_findings.json -o outputs/cbom.cdx.json
python3 scanner/risk_report.py outputs/cbom.cdx.json -o outputs/risk-report.md
```

## Learning goals

1. Find cryptographic API usages in Java source code.
2. Normalize raw algorithm strings into CBOM assets.
3. Generate a CycloneDX 1.7 CBOM with `cryptographic-asset` components.
4. Classify deprecated and quantum-vulnerable cryptography.
5. Discuss PQC migration priorities.
