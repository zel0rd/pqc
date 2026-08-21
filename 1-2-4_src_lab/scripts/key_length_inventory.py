#!/usr/bin/env python3
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
OUT_JSON = Path("results/key_length_inventory.json")
OUT_CSV = Path("results/key_length_inventory.csv")

AES_FUNC_RE = re.compile(r"EVP_aes_(128|192|256)_([a-z0-9]+)\s*\(")
AES_ARRAY_RE = re.compile(r"unsigned\s+char\s+(\w*key\w*)\s*\[\s*(16|24|32)\s*\]", re.IGNORECASE)
RSA_RE = re.compile(r"RSA_generate_key_ex\s*\([^,]+,\s*(1024|2048|3072|4096)\s*,")
ECC_RE = re.compile(r"NID_(X9_62_prime256v1|secp256r1|secp384r1|secp521r1|secp256k1)")

ECC_MAP = {
    "X9_62_prime256v1": ("P-256 / prime256v1 / secp256r1", 256, "PQC Migration"),
    "secp256r1": ("P-256 / secp256r1", 256, "PQC Migration"),
    "secp384r1": ("P-384 / secp384r1", 384, "PQC Migration"),
    "secp521r1": ("P-521 / secp521r1", 521, "PQC Migration"),
    "secp256k1": ("secp256k1", 256, "PQC Migration"),
}


def severity_for_rsa(bits: int) -> str:
    if bits < 2048:
        return "HIGH"
    return "INFO"


def severity_for_aes(bits: int, mode: str = "") -> str:
    if mode == "ecb":
        return "HIGH"
    if bits < 128:
        return "HIGH"
    return "INFO"


def scan_file(path: Path):
    findings = []
    lines = path.read_text(errors="ignore").splitlines()
    for line_no, line in enumerate(lines, start=1):
        for m in AES_FUNC_RE.finditer(line):
            bits = int(m.group(1))
            mode = m.group(2)
            findings.append({
                "asset_type": "AES",
                "algorithm": f"AES-{bits}-{mode.upper()}",
                "key_bits": bits,
                "source": "OpenSSL EVP function",
                "severity": severity_for_aes(bits, mode),
                "file": str(path),
                "line": line_no,
                "evidence": line.strip(),
                "recommendation": "Avoid ECB; prefer AEAD modes such as AES-GCM. Manage keys outside source code."
            })
        for m in AES_ARRAY_RE.finditer(line):
            key_bytes = int(m.group(2))
            findings.append({
                "asset_type": "AES key candidate",
                "algorithm": f"AES-{key_bytes * 8} key buffer",
                "key_bits": key_bytes * 8,
                "source": "C key buffer length",
                "severity": "HIGH",
                "file": str(path),
                "line": line_no,
                "evidence": line.strip(),
                "recommendation": "A fixed-size key buffer may indicate a hardcoded key; verify key origin and use KMS/HSM/secret manager."
            })
        for m in RSA_RE.finditer(line):
            bits = int(m.group(1))
            findings.append({
                "asset_type": "RSA",
                "algorithm": f"RSA-{bits}",
                "key_bits": bits,
                "source": "RSA_generate_key_ex bits argument",
                "severity": severity_for_rsa(bits),
                "file": str(path),
                "line": line_no,
                "evidence": line.strip(),
                "recommendation": "Inventory RSA as a PQC migration target. RSA-1024 is also classically weak and should be removed."
            })
        for m in ECC_RE.finditer(line):
            nid = m.group(1)
            curve, bits, sev = ECC_MAP[nid]
            findings.append({
                "asset_type": "ECC",
                "algorithm": curve,
                "key_bits": bits,
                "source": "OpenSSL curve NID",
                "severity": sev,
                "file": str(path),
                "line": line_no,
                "evidence": line.strip(),
                "recommendation": "Inventory ECC as a PQC migration target; consider ML-KEM/hybrid for key exchange and ML-DSA/SLH-DSA for signatures."
            })
    return findings


def main():
    findings = []
    for path in ROOT.rglob("*"):
        if path.is_file() and path.suffix in {".c", ".h", ".cpp", ".hpp"} and "results" not in path.parts:
            findings.extend(scan_file(path))

    Path("results").mkdir(exist_ok=True)
    OUT_JSON.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["asset_type", "algorithm", "key_bits", "source", "severity", "file", "line", "evidence", "recommendation"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    print(f"Key-length findings: {len(findings)}")
    for item in findings:
        print(f"[{item['severity']}] {item['asset_type']} {item['algorithm']} ({item['key_bits']} bits) {item['file']}:{item['line']}")


if __name__ == "__main__":
    main()
