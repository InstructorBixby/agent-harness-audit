"""Baselines.

An audit of a real harness produces findings that will be open for a
quarter. A gate that fails on all of them gets switched off within a
week, so the useful gate fails on *new* findings and the baseline is
the record of what was already known.

A baseline entry is keyed on (check, a stable fingerprint of the
evidence) rather than on the title, because titles get reworded and a
reworded title should not silently un-baseline a finding.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ahaudit.findings import Finding


def fingerprint(finding: Finding) -> str:
    """Stable across rewordings, sensitive to the structure."""
    material = {
        "check": finding.check,
        # The parts of the evidence that identify *which* instance this
        # is -- a context name, a tool name -- and not the parts that
        # describe it.
        "where": {k: v for k, v in sorted(finding.evidence.items())
                  if k in ("context", "tools", "names", "pairs",
                           "triggers", "concurrency", "approval_scope")},
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class Baseline:
    entries: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "Baseline":
        return cls({fingerprint(f): f.title for f in findings})

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(dict(raw.get("accepted", {})))

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(json.dumps({"accepted": self.entries}, indent=1,
                                sort_keys=True), encoding="utf-8")
        return p

    def is_new(self, finding: Finding) -> bool:
        return fingerprint(finding) not in self.entries

    def split(self, findings: list[Finding]
              ) -> tuple[list[Finding], list[Finding]]:
        new = [f for f in findings if self.is_new(f)]
        known = [f for f in findings if not self.is_new(f)]
        return new, known

    def stale(self, findings: list[Finding]) -> list[str]:
        """Baselined findings that no longer appear.

        Worth reporting: either they were fixed, in which case the
        baseline should shrink, or a check regressed and stopped
        finding them.
        """
        present = {fingerprint(f) for f in findings}
        return sorted(title for fp, title in self.entries.items()
                      if fp not in present)
