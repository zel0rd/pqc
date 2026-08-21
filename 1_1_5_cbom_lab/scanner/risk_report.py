#!/usr/bin/env python3
"""Generate a simple Markdown risk report from a teaching CBOM."""
import argparse
import json
from pathlib import Path


def prop(comp, name, default=""):
    for p in comp.get("properties", []):
        if p.get("name") == name:
            return p.get("value", default)
    return default


def priority(comp):
    policy = prop(comp, "security:policy-status")
    quantum = prop(comp, "security:quantum-vulnerable")
    name = comp.get("name", "")
    if policy == "prohibited":
        return "High", "금지 알고리즘 제거"
    if quantum == "true":
        if "RSA" in name or "EC" in name or "Elliptic" in name:
            return "High", "PQC 또는 hybrid 전환 검토"
        return "Medium", "양자 취약성 영향 분석"
    if policy.startswith("review"):
        return "Medium", "파라미터와 사용 맥락 검토"
    return "Low", "현행 유지 및 모니터링"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cbom")
    ap.add_argument("-o", "--output", default="risk-report.md")
    args = ap.parse_args()
    bom = json.loads(Path(args.cbom).read_text(encoding="utf-8"))
    rows = []
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        pri, action = priority(c)
        rows.append((pri, c.get("name", ""), c.get("cryptoProperties", {}).get("assetType", ""), prop(c,"cbomlab:source-file"), prop(c,"security:policy-status"), prop(c,"security:quantum-vulnerable"), action))

    order = {"High": 0, "Medium": 1, "Low": 2}
    rows.sort(key=lambda r: order.get(r[0], 9))
    lines = ["# CBOM Risk Report", "", "| Priority | Asset | Type | Location | Policy | Quantum-vulnerable | Action |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| " + " | ".join(r) + " |")
    lines += ["", "## Interpretation", "", "- High: 즉시 제거 또는 PQC/hybrid 전환 계획 수립 대상", "- Medium: 파라미터, 프로토콜 버전, 운영 맥락 검토 대상", "- Low: 현행 유지 가능하나 지속적 모니터링 필요"]
    Path(args.output).write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {args.output}")

if __name__ == "__main__":
    main()
