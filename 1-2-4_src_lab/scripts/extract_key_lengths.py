#!/usr/bin/env python3
"""Extract AES/RSA/ECC key-length hints from C/OpenSSL source code.

This is a teaching-oriented static analyzer. It combines API-name patterns,
array-size patterns, and curve-name mappings to infer crypto asset key lengths.
"""
import csv
import json
import re
import sys
from pathlib import Path

SCAN_EXTENSIONS = {".c", ".h", ".cpp", ".hpp"}
IGNORE_DIRS = {".git", "results"}

ECC_CURVE_BITS = {
    "NID_X9_62_prime256v1": 256,
    "NID_secp256r1": 256,
    "NID_secp384r1": 384,
    "NID_secp521r1": 521,
    "NID_secp224r1": 224,
    "NID_X25519": 255,
    "NID_X448": 448,
}

PATTERNS = [
    {
        "asset_type": "symmetric-cipher",
        "algorithm": "AES",
        "kind": "OpenSSL EVP cipher API",
        "regex": re.compile(r"EVP_aes_(128|192|256)_([a-z0-9]+)\s*\("),
        "extract": lambda m: (int(m.group(1)), f"AES-{m.group(1)}-{m.group(2).upper()}"),
    },
    {
        "asset_type": "symmetric-key",
        "algorithm": "AES",
        "kind": "C byte array key length",
        "regex": re.compile(r"unsigned\s+char\s+([A-Za-z0-9_]*key[A-Za-z0-9_]*)\s*\[\s*(16|24|32)\s*\]", re.IGNORECASE),
        "extract": lambda m: (int(m.group(2)) * 8, f"{m.group(1)} array {m.group(2)} bytes"),
    },
    {
        "asset_type": "public-key",
        "algorithm": "RSA",
        "kind": "RSA key generation bits",
        "regex": re.compile(r"RSA_generate_key_ex\s*\([^,]+,\s*(1024|2048|3072|4096|7680|15360)\s*,"),
        "extract": lambda m: (int(m.group(1)), f"RSA-{m.group(1)}"),
    },
]


def should_scan(path: Path) -> bool:
    if any(part in IGNORE_DIRS for part in path.parts):
        return False
    return path.is_file() and path.suffix in SCAN_EXTENSIONS


def classify(asset_type: str, algorithm: str, bits: int) -> tuple[str, str]:
    if algorithm == "AES":
        if bits < 128:
            return "HIGH", "AES key length below 128 bits is not acceptable."
        if bits == 128:
            return "MEDIUM", "AES-128 is common, but AES-256 may be preferred for long-term confidentiality."
        return "INFO", "AES key length is 192 bits or higher. Confirm mode and key management."

    if algorithm == "RSA":
        if bits < 2048:
            return "HIGH", "RSA key length below 2048 bits is weak. Replace immediately."
        if bits == 2048:
            return "PQC_MIGRATION", "RSA-2048 is common but should be inventoried for PQC migration."
        return "PQC_MIGRATION", "RSA key detected. Plan PQC or hybrid migration regardless of classical key size."

    if algorithm == "ECC":
        return "PQC_MIGRATION", "ECC curve detected. Plan PQC or hybrid migration."

    return "INFO", "Review detected cryptographic asset."


def scan_file(path: Path):
    findings = []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return findings

    for line_no, line in enumerate(lines, start=1):
        for rule in PATTERNS:
            for match in rule["regex"].finditer(line):
                bits, detail = rule["extract"](match)
                severity, recommendation = classify(rule["asset_type"], rule["algorithm"], bits)
                findings.append({
                    "asset_type": rule["asset_type"],
                    "algorithm": rule["algorithm"],
                    "key_length_bits": bits,
                    "detail": detail,
                    "detection_method": rule["kind"],
                    "severity": severity,
                    "file": str(path),
                    "line": line_no,
                    "evidence": line.strip()[:240],
                    "recommendation": recommendation,
                })

        for curve, bits in ECC_CURVE_BITS.items():
            if curve in line:
                severity, recommendation = classify("public-key", "ECC", bits)
                findings.append({
                    "asset_type": "public-key",
                    "algorithm": "ECC",
                    "key_length_bits": bits,
                    "detail": curve,
                    "detection_method": "OpenSSL curve NID mapping",
                    "severity": severity,
                    "file": str(path),
                    "line": line_no,
                    "evidence": line.strip()[:240],
                    "recommendation": recommendation,
                })

    return findings


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    findings = []
    for path in root.rglob("*"):
        if should_scan(path):
            findings.extend(scan_file(path))

    Path("results").mkdir(exist_ok=True)
    json_path = Path("results/key_length_findings.json")
    csv_path = Path("results/key_length_findings.csv")

    with json_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    fieldnames = [
        "asset_type", "algorithm", "key_length_bits", "detail", "detection_method",
        "severity", "file", "line", "evidence", "recommendation"
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    print(f"Key length findings: {len(findings)}")
    for item in findings:
        print(
            f"[{item['severity']}] {item['algorithm']} {item['key_length_bits']} bits "
            f"{item['file']}:{item['line']} - {item['detail']}"
        )


if __name__ == "__main__":
    main()
