#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def load_policy(path: Path) -> dict:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[ERROR] Cannot load policy: {e}")
        sys.exit(2)

def excluded(path: Path, excludes: list[str]) -> bool:
    parts = set(path.parts)
    return any(x in parts for x in excludes)

def line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1

def line_text(text: str, n: int) -> str:
    lines = text.splitlines()
    return lines[n - 1].strip() if 1 <= n <= len(lines) else ""

def scan_file(path: Path, rules: list[dict]) -> list[dict]:
    findings = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    for rule in rules:
        for pattern in rule.get("patterns", []):
            regex = re.compile(pattern)
            for m in regex.finditer(text):
                n = line_no(text, m.start())
                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "file": str(path),
                    "line": n,
                    "matched": m.group(0),
                    "source": line_text(text, n),
                    "message": rule["message"],
                    "recommendation": rule["recommendation"],
                })
    return findings

def scan(root: Path, policy: dict) -> list[dict]:
    findings = []
    exts = set(policy.get("scan_extensions", []))
    excludes = policy.get("exclude_paths", [])
    for p in root.rglob("*"):
        if p.is_file() and p.suffix in exts and not excluded(p, excludes):
            print(f"[SCAN] {p}")
            findings.extend(scan_file(p, policy["rules"]))
    return findings

def summary(findings: list[dict]) -> dict:
    return {
        "total": len(findings),
        "severity": dict(Counter(f["severity"] for f in findings)),
        "category": dict(Counter(f["category"] for f in findings)),
    }

def annotate(findings: list[dict]) -> None:
    for f in findings:
        level = "error" if f["severity"] in {"critical", "high"} else "warning"
        msg = f"{f['name']}: {f['message']} Recommendation: {f['recommendation']}"
        print(f"::{level} file={f['file']},line={f['line']},title={f['rule_id']}::{msg}")

def write_reports(findings: list[dict], json_path: Path, md_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "summary": summary(findings), "findings": findings}
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# Crypto Policy Scan Report", "", f"- Total findings: {len(findings)}", ""]
    if not findings:
        lines.append("No policy violations detected.")
    else:
        for i, f in enumerate(findings, 1):
            lines += [
                f"## {i}. {f['rule_id']} - {f['name']}",
                f"- Severity: `{f['severity']}`",
                f"- Category: `{f['category']}`",
                f"- Location: `{f['file']}:{f['line']}`",
                f"- Matched: `{f['matched']}`",
                f"- Source: `{f['source']}`",
                f"- Recommendation: {f['recommendation']}",
                "",
            ]
    md_path.write_text("\n".join(lines), encoding="utf-8")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--policy", default="policy/crypto-policy.yml")
    ap.add_argument("--json-report", default="reports/crypto-report.json")
    ap.add_argument("--markdown-report", default="reports/crypto-report.md")
    ap.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "never"])
    args = ap.parse_args()

    policy = load_policy(Path(args.policy))
    findings = scan(Path(args.root), policy)
    annotate(findings)
    write_reports(findings, Path(args.json_report), Path(args.markdown_report))

    s = summary(findings)
    print("\n=== Crypto Scan Summary ===")
    print(f"Total findings: {s['total']}")
    for sev in ["critical", "high", "medium", "low"]:
        print(f"{sev}: {s['severity'].get(sev, 0)}")

    if args.fail_on != "never":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK.get(f["severity"], 0) >= threshold for f in findings):
            print("[FAIL] Crypto policy violation detected.")
            return 1
    print("[PASS] Crypto policy check passed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
