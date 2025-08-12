"""JSON output, in the shape the schema describes."""
from __future__ import annotations

import json
from pathlib import Path

import ahaudit
from ahaudit.findings import Finding, sort_findings
from ahaudit.model import Harness

SCHEMA_VERSION = "1"
SCHEMA_PATH = Path(__file__).parent / "schema" / "finding.schema.json"


def document(harness: Harness, findings: list[Finding]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "harness": harness.name,
        "generated_by": {"tool": "agent-harness-audit",
                         "version": ahaudit.__version__},
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }


def dumps(harness: Harness, findings: list[Finding]) -> str:
    return json.dumps(document(harness, findings), indent=1,
                      sort_keys=False)


def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
