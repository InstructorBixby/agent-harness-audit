"""SARIF 2.1.0 output.

Not because SARIF is pleasant, but because a client whose pipeline
already ingests it will look at these findings without anyone building
anything, and a finding nobody looks at is not a finding.

Mapping decisions worth writing down:
  - one rule per check id, not per finding
  - severity maps to `level` plus a `rank`, because SARIF's three
    levels lose the difference between high and critical
  - the manifest path is the artifact location; there is no line
    number, and inventing one would be worse than omitting it
"""
from __future__ import annotations

import json

import ahaudit
from ahaudit.checks import TITLES
from ahaudit.findings import Finding, Severity, sort_findings

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
RANK = {
    Severity.CRITICAL: 95.0,
    Severity.HIGH: 80.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 25.0,
    Severity.INFO: 5.0,
}


def document(findings: list[Finding], *, manifest_path: str) -> dict:
    used = sorted({f.check for f in findings})
    rules = [{
        "id": check,
        "name": check.replace("-", ""),
        "shortDescription": {"text": TITLES.get(check, check)},
        "helpUri": "https://git.c01n31.net/c01n31pan1c/"
                   "agent-harness-audit/-/blob/main/docs/checks.md",
    } for check in used]

    results = []
    for f in sort_findings(findings):
        results.append({
            "ruleId": f.check,
            "level": LEVEL[f.severity],
            "rank": RANK[f.severity],
            "message": {"text": f"{f.title}. {f.claim}"},
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "taxonomy": f.taxonomy,
                "remediation": f.remediation,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": manifest_path}
                }
            }],
        })

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "agent-harness-audit",
                "version": ahaudit.__version__,
                "informationUri": "https://git.c01n31.net/"
                                  "c01n31pan1c/agent-harness-audit",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def dumps(findings: list[Finding], *, manifest_path: str) -> str:
    return json.dumps(document(findings, manifest_path=manifest_path),
                      indent=1)
