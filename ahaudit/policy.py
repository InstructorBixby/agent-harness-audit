"""Severity policy.

The tool cannot know what a tool reaches in the client's world:
`send_email` to one fixed internal address and `send_email` to an
arbitrary recipient are the same manifest entry unless the manifest
says otherwise. So the defaults are defensible and overridable, and an
override is recorded in the output rather than applied silently.

Two things a policy can do:
  - raise or lower a check's severity
  - mark a check as not applicable, with a reason
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ahaudit.findings import Finding, Severity


@dataclass(slots=True)
class Policy:
    severities: dict[str, Severity] = field(default_factory=dict)
    disabled: dict[str, str] = field(default_factory=dict)

    def applies(self, check: str) -> bool:
        return check not in self.disabled

    def severity_for(self, finding: Finding) -> Severity:
        return self.severities.get(finding.check, finding.severity)

    def apply(self, findings: list[Finding]) -> list[Finding]:
        out = []
        for f in findings:
            if not self.applies(f.check):
                continue
            new = self.severity_for(f)
            if new is not f.severity:
                f = Finding(**{**vars_of(f), "severity": new})
                f.evidence = dict(f.evidence)
                f.evidence["severity_overridden_from"] = \
                    vars_of(f).get("severity", "")
            out.append(f)
        return out


def vars_of(f: Finding) -> dict:
    return {"check": f.check, "title": f.title, "severity": f.severity,
            "claim": f.claim, "evidence": f.evidence,
            "remediation": f.remediation, "taxonomy": f.taxonomy,
            "confidence": f.confidence}


def load(path: str | Path) -> Policy:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    severities = {k: Severity(v)
                  for k, v in (raw.get("severities") or {}).items()}
    disabled = dict(raw.get("disabled") or {})
    for check, reason in disabled.items():
        if not reason:
            raise ValueError(
                f"policy: disabling {check} needs a reason; a check "
                f"turned off without one is indistinguishable from a "
                f"check that never ran")
    return Policy(severities=severities, disabled=disabled)
