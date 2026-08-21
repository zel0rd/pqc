#!/usr/bin/env python3
"""Simple Java crypto API scanner for a CBOM lab.

This is intentionally lightweight for teaching. It searches Java source files for
common JCA/JCE entry points and emits normalized crypto findings as JSON.
"""
import argparse
import json
import re
from pathlib import Path

PATTERNS = [
    ("Cipher.getInstance", re.compile(r'Cipher\.getInstance\("([^"]+)"\)')),
    ("Signature.getInstance", re.compile(r'Signature\.getInstance\("([^"]+)"\)')),
    ("MessageDigest.getInstance", re.compile(r'MessageDigest\.getInstance\("([^"]+)"\)')),
    ("Mac.getInstance", re.compile(r'Mac\.getInstance\("([^"]+)"\)')),
    ("KeyPairGenerator.getInstance", re.compile(r'KeyPairGenerator\.getInstance\("([^"]+)"\)')),
    ("KeyGenerator.getInstance", re.compile(r'KeyGenerator\.getInstance\("([^"]+)"\)')),
    ("KeyAgreement.getInstance", re.compile(r'KeyAgreement\.getInstance\("([^"]+)"\)')),
    ("SecretKeyFactory.getInstance", re.compile(r'SecretKeyFactory\.getInstance\("([^"]+)"\)')),
    ("SSLContext.getInstance", re.compile(r'SSLContext\.getInstance\("([^"]+)"\)')),
    ("KeyStore.getInstance", re.compile(r'KeyStore\.getInstance\("([^"]+)"\)')),
]

INIT_PATTERN = re.compile(r'\.initialize\((\d+)[,\)]')
CURVE_PATTERN = re.compile(r'ECGenParameterSpec\("([^"]+)"\)')

NORMALIZATION = {
    "AES/GCM/NoPadding": {"name": "AES-256-GCM", "primitive": "authenticated-encryption", "family": "AES", "parameter": "256", "quantum": False, "policy": "allowed"},
    "AES": {"name": "AES", "primitive": "block-cipher", "family": "AES", "parameter": "unknown", "quantum": False, "policy": "review"},
    "SHA-1": {"name": "SHA-1", "primitive": "hash", "family": "SHA1", "parameter": "160", "quantum": False, "policy": "prohibited"},
    "SHA-256": {"name": "SHA-256", "primitive": "hash", "family": "SHA2", "parameter": "256", "quantum": False, "policy": "allowed"},
    "HmacSHA256": {"name": "HMAC-SHA-256", "primitive": "mac", "family": "HMAC", "parameter": "SHA-256", "quantum": False, "policy": "allowed"},
    "SHA256withRSA": {"name": "RSA-PKCS1-v1_5-SHA-256", "primitive": "signature", "family": "RSASSA-PKCS1-v1_5", "parameter": "2048?", "quantum": True, "policy": "migrate"},
    "RSA": {"name": "RSA", "primitive": "public-key", "family": "RSA", "parameter": "unknown", "quantum": True, "policy": "migrate"},
    "EC": {"name": "Elliptic Curve", "primitive": "public-key", "family": "EC", "parameter": "unknown", "quantum": True, "policy": "migrate"},
    "PBKDF2WithHmacSHA256": {"name": "PBKDF2-HMAC-SHA-256", "primitive": "kdf", "family": "PBKDF2", "parameter": "HMAC-SHA-256", "quantum": False, "policy": "review-parameters"},
    "TLSv1.2": {"name": "TLS 1.2", "primitive": "protocol", "family": "TLS", "parameter": "1.2", "quantum": "depends-on-cipher-suite", "policy": "review"},
    "TLSv1.3": {"name": "TLS 1.3", "primitive": "protocol", "family": "TLS", "parameter": "1.3", "quantum": "depends-on-cipher-suite", "policy": "allowed"},
    "PKCS12": {"name": "PKCS#12 Keystore", "primitive": "keystore", "family": "PKCS12", "parameter": "n/a", "quantum": False, "policy": "allowed"},
}


def normalize(raw: str, context: str):
    n = dict(NORMALIZATION.get(raw, {"name": raw, "primitive": "unknown", "family": raw, "parameter": "unknown", "quantum": "unknown", "policy": "review"}))
    n["raw"] = raw
    n["api"] = context
    return n


def scan(root: Path):
    findings = []
    for path in sorted(root.rglob("*.java")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            for api, pat in PATTERNS:
                for m in pat.finditer(line):
                    raw = m.group(1)
                    item = normalize(raw, api)
                    # Look ahead/back for common parameter clues used in this teaching example.
                    window = "\n".join(lines[max(0, idx-5):min(len(lines), idx+8)])
                    init = INIT_PATTERN.search(window)
                    curve = CURVE_PATTERN.search(window)
                    if raw in ("RSA", "AES") and init:
                        item["parameter"] = init.group(1)
                        item["name"] = f"{raw}-{init.group(1)}"
                    if raw == "EC" and curve:
                        item["parameter"] = curve.group(1)
                        item["name"] = f"EC-{curve.group(1)}"
                    item.update({"file": str(path.relative_to(root)), "line": idx})
                    findings.append(item)
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="Java source root")
    ap.add_argument("-o", "--output", default="crypto_findings.json")
    args = ap.parse_args()
    findings = scan(Path(args.source))
    Path(args.output).write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(findings)} findings to {args.output}")

if __name__ == "__main__":
    main()
