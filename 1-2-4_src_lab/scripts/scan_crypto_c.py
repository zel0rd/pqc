#!/usr/bin/env python3
import csv
import json
import re
import sys
from pathlib import Path

SCAN_EXTENSIONS = {".c", ".h", ".cpp", ".hpp"}
IGNORE_DIRS = {".git", "results"}

RULES = [
    {
        "id": "C-CRYPTO-001",
        "name": "MD5 API or constant detected",
        "severity": "HIGH",
        "pattern": re.compile(r"\bMD5\b|MD5_DIGEST_LENGTH"),
        "recommendation": "Avoid MD5. Use SHA-256 or stronger where appropriate."
    },
    {
        "id": "C-CRYPTO-002",
        "name": "SHA-1 API or constant detected",
        "severity": "MEDIUM",
        "pattern": re.compile(r"\bSHA1\b|SHA_DIGEST_LENGTH"),
        "recommendation": "Avoid SHA-1. Use SHA-256 or stronger."
    },
    {
        "id": "C-CRYPTO-003",
        "name": "AES ECB mode detected",
        "severity": "HIGH",
        "pattern": re.compile(r"EVP_aes_(128|192|256)_ecb|AES_ecb_encrypt"),
        "recommendation": "Avoid ECB. Use AEAD modes such as AES-GCM."
    },
    {
        "id": "C-CRYPTO-004",
        "name": "RSA API detected",
        "severity": "INFO",
        "pattern": re.compile(r"\bRSA_new\b|RSA_generate_key_ex|EVP_PKEY_RSA|RSA_F4"),
        "recommendation": "Inventory RSA usage and plan PQC or hybrid migration."
    },
    {
        "id": "C-CRYPTO-005",
        "name": "ECC API detected",
        "severity": "INFO",
        "pattern": re.compile(r"EC_KEY|EC_GROUP|ECDSA|ECDH|NID_X9_62_prime256v1|NID_secp384r1"),
        "recommendation": "Inventory ECC usage and plan PQC or hybrid migration."
    },
    {
        "id": "C-PARAM-001",
        "name": "P-256 domain parameter detected",
        "severity": "INFO",
        "pattern": re.compile(
            r"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF|"
            r"5AC635D8AA3A93E7B3EBBD55769886BC|"
            r"6B17D1F2E12C4247F8BCE6E563A440F2",
            re.IGNORECASE
        ),
        "recommendation": "P-256 parameter detected. Check for ECC implementation."
    },
    {
        "id": "C-PARAM-002",
        "name": "RSA public exponent 65537 detected",
        "severity": "INFO",
        "pattern": re.compile(r"\bRSA_F4\b|010001|65537"),
        "recommendation": "RSA public exponent candidate. Confirm with modulus/private exponent context."
    },
    {
        "id": "C-SECRET-001",
        "name": "Hardcoded 16/24/32-byte key candidate",
        "severity": "HIGH",
        "pattern": re.compile(r'["\'][A-Za-z0-9+/=]{16}["\']|["\'][A-Za-z0-9+/=]{24}["\']|["\'][A-Za-z0-9+/=]{32}["\']'),
        "recommendation": "Do not hardcode symmetric keys. Use KMS, HSM, or a secret manager."
    },
    {
        "id": "C-KEYLEN-001",
        "name": "AES key length from EVP function",
        "severity": "INFO",
        "pattern": re.compile(r"EVP_aes_(128|192|256)_"),
        "recommendation": "Extract AES key length from EVP_aes_<bits>_<mode>() and record it in crypto inventory."
    },
    {
        "id": "C-KEYLEN-002",
        "name": "RSA key length from RSA_generate_key_ex",
        "severity": "INFO",
        "pattern": re.compile(r"RSA_generate_key_ex\s*\([^,]+,\s*(1024|2048|3072|4096)\s*,"),
        "recommendation": "Extract RSA modulus length and classify RSA as a PQC migration target."
    },
    {
        "id": "C-KEYLEN-003",
        "name": "ECC curve key length from OpenSSL NID",
        "severity": "INFO",
        "pattern": re.compile(r"NID_(X9_62_prime256v1|secp256r1|secp384r1|secp521r1|secp256k1)"),
        "recommendation": "Map OpenSSL curve NID to ECC key length and classify it as a PQC migration target."
    },
]


def should_scan(path: Path) -> bool:
    if any(part in IGNORE_DIRS for part in path.parts):
        return False
    return path.is_file() and path.suffix in SCAN_EXTENSIONS


def scan_file(path: Path):
    findings = []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return findings

    for line_no, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "file": str(path),
                    "line": line_no,
                    "evidence": line.strip()[:240],
                    "recommendation": rule["recommendation"]
                })
    return findings


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    findings = []
    for path in root.rglob("*"):
        if should_scan(path):
            findings.extend(scan_file(path))

    Path("results").mkdir(exist_ok=True)

    with open("results/c_crypto_findings.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    with open("results/c_crypto_findings.csv", "w", newline="", encoding="utf-8") as f:
        fieldnames = ["rule_id", "name", "severity", "file", "line", "evidence", "recommendation"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    print(f"Findings: {len(findings)}")
    for item in findings:
        print(f"[{item['severity']}] {item['rule_id']} {item['file']}:{item['line']} - {item['name']}")


if __name__ == "__main__":
    main()
