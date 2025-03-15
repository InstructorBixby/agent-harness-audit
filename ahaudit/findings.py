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
    check: str                    # AHA-001
    title: str
    severity: Severity
    # The structural claim, in one sentence, with no hedging.
    claim: str
    # Where in the model it came from, so a reader can argue with it.
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    # Ids from the llm-redteam-notes taxonomy, so a report can carry
    # one argument instead of two.
    taxonomy: list[str] = field(default_factory=list)
    confidence: str = "declared"  # declared | observed | inferred

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.rank, f.check))
