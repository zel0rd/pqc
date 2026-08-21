#!/usr/bin/env python3
"""Generate a teaching-oriented CycloneDX 1.7 CBOM from crypto findings.

This script is intentionally simple and uses CycloneDX cryptoProperties plus
organization-defined properties for policy/risk fields.
"""
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def safe_ref(s: str) -> str:
    s = s.lower().replace("#", "sharp")
    return re.sub(r"[^a-z0-9_.:-]+", "-", s).strip("-")


def asset_type(primitive: str):
    if primitive == "protocol":
        return "protocol"
    if primitive == "keystore":
        return "related-crypto-material"
    return "algorithm"


def component_from_finding(f):
    primitive = f.get("primitive", "unknown")
    atype = asset_type(primitive)
    bom_ref = f"crypto:{safe_ref(f.get('name', f.get('raw','unknown')))}:{safe_ref(f.get('file','unknown'))}:{f.get('line','0')}"
    cp = {"assetType": atype}
    if atype == "algorithm":
        cp["algorithmProperties"] = {
            "primitive": primitive,
            "algorithmFamily": f.get("family", "unknown"),
            "parameterSetIdentifier": str(f.get("parameter", "unknown"))
        }
    elif atype == "protocol":
        cp["protocolProperties"] = {
            "type": f.get("family", "protocol").lower(),
            "version": str(f.get("parameter", "unknown"))
        }
    else:
        cp["relatedCryptoMaterialProperties"] = {
            "type": "keystore",
            "algorithmRef": "unknown"
        }
    props = [
        {"name": "cbomlab:detected-by", "value": "java-static-analysis"},
        {"name": "cbomlab:source-file", "value": f.get("file", "unknown")},
        {"name": "cbomlab:source-line", "value": str(f.get("line", "unknown"))},
        {"name": "cbomlab:raw-api", "value": f.get("api", "unknown")},
        {"name": "cbomlab:raw-value", "value": f.get("raw", "unknown")},
        {"name": "security:policy-status", "value": str(f.get("policy", "review"))},
        {"name": "security:quantum-vulnerable", "value": str(f.get("quantum", "unknown")).lower()},
    ]
    return {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": f.get("name", f.get("raw", "unknown")),
        "cryptoProperties": cp,
        "properties": props
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("-o", "--output", default="cbom.cdx.json")
    ap.add_argument("--service-name", default="user-auth-api")
    ap.add_argument("--service-version", default="1.0.0")
    ap.add_argument("--endpoint", default="https://auth.example.com")
    args = ap.parse_args()

    findings = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    components = [component_from_finding(f) for f in findings]
    refs = [c["bom-ref"] for c in components]

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "component": {
                "type": "application",
                "bom-ref": f"app:{safe_ref(args.service_name)}",
                "name": args.service_name,
                "version": args.service_version
            },
            "tools": {
                "components": [
                    {"type": "application", "name": "cbom-lab-java-scanner", "version": "0.1.0"}
                ]
            }
        },
        "services": [
            {
                "bom-ref": f"service:{safe_ref(args.service_name)}:https",
                "name": f"{args.service_name} HTTPS endpoint",
                "endpoints": [args.endpoint],
                "authenticated": True,
                "x-trust-boundary": True,
                "properties": [
                    {"name": "security:exposure", "value": "internet-facing"},
                    {"name": "security:data-lifetime", "value": "long"}
                ]
            }
        ],
        "components": components,
        "dependencies": [
            {"ref": f"app:{safe_ref(args.service_name)}", "dependsOn": refs},
            {"ref": f"service:{safe_ref(args.service_name)}:https", "dependsOn": refs}
        ]
    }
    Path(args.output).write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote CBOM with {len(components)} crypto assets to {args.output}")

if __name__ == "__main__":
    main()
