"""Findings.

A finding is a structural claim about the harness, with evidence that
points at the part of the model it came from. Severity is advisory --
the tool cannot know what the tools reach in the client's world -- but
the ordering is useful and the defaults are defensible.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass
class Finding:
    check: str
    title: str
    severity: Severity
    claim: str
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    taxonomy: list[str] = field(default_factory=list)
    confidence: str = "declared"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Worst first, then stable.

    Two findings from the same check at the same severity used to come
    out in whichever order the dict happened to yield, so the same
    manifest produced different reports on different runs and the
    committed sample reports churned. Title and then the evidence's
    string form break the tie.
    """
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, f.check, f.title,
                       repr(sorted(f.evidence.items()))))
