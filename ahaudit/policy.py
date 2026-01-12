"""Severity policy.

The tool cannot know what a tool reaches in the client's world:
`send_email` to one fixed internal address and `send_email` to an
arbitrary recipient are the same manifest entry unless the manifest
says otherwise. So the defaults are defensible and overridable, and an
override is recorded in the output rather than applied silently.

Two things a policy can do:
  - raise or lower a check's severity
  - mark a check as not applicable, with a mandatory reason

Both are visible in the finding. A tool whose severities can be edited
invisibly is a tool whose output means nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

from ahaudit.findings import Finding, Severity


class PolicyError(ValueError):
    pass


@dataclass(slots=True)
class Policy:
    severities: dict[str, Severity] = field(default_factory=dict)
    disabled: dict[str, str] = field(default_factory=dict)

    def applies(self, check: str) -> bool:
        return check not in self.disabled

    def apply(self, findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            if not self.applies(f.check):
                continue
            target = self.severities.get(f.check)
            if target is None or target is f.severity:
                out.append(f)
                continue
            evidence = dict(f.evidence)
            evidence["severity_overridden"] = {
                "from": f.severity.value, "to": target.value}
            out.append(replace(f, severity=target, evidence=evidence))
        return out

    def notes(self) -> list[str]:
        return [f"{check} disabled: {reason}"
                for check, reason in sorted(self.disabled.items())]


def load(path: str | Path) -> Policy:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    unknown = sorted(set(raw) - {"severities", "disabled"})
    if unknown:
        raise PolicyError(
            f"policy: unknown key(s) {', '.join(unknown)}")
    try:
        severities = {k: Severity(v)
                      for k, v in (raw.get("severities") or {}).items()}
    except ValueError as exc:
        raise PolicyError(f"policy: {exc}") from None
    disabled = dict(raw.get("disabled") or {})
    for check, reason in disabled.items():
        if not reason:
            raise PolicyError(
                f"policy: disabling {check} needs a reason; a check "
                f"turned off without one is indistinguishable from a "
                f"check that never ran")
    return Policy(severities=severities, disabled=disabled)
