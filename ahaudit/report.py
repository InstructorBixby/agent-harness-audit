"""Rendering findings."""
from __future__ import annotations

from collections import Counter

from ahaudit.findings import Finding, Severity, sort_findings
from ahaudit.model import Harness


def text_summary(harness: Harness, findings: list[Finding]) -> str:
    lines = [f"harness: {harness.name}",
             f"{len(findings)} finding(s)", ""]
    counts = Counter(f.severity.value for f in findings)
    if counts:
        lines.append("  ".join(
            f"{s.value}={counts.get(s.value, 0)}"
            for s in reversed(list(Severity))
            if counts.get(s.value)))
        lines.append("")
    for f in sort_findings(findings):
        lines.append(f"[{f.severity.value.upper():8}] {f.check}  "
                     f"{f.title}")
    return "\n".join(lines)


def markdown(harness: Harness, findings: list[Finding]) -> str:
    out = [f"# Harness audit: {harness.name}", ""]
    counts = Counter(f.severity.value for f in findings)
    out += ["| severity | count |", "|---|---|"]
    for s in reversed(list(Severity)):
        out.append(f"| {s.value} | {counts.get(s.value, 0)} |")
    out.append("")

    if not findings:
        out += ["No findings. Note what that does and does not mean: "
                "every check here is a question about the declared "
                "manifest, so a clean result means the declaration is "
                "sound, not that the implementation matches it.", ""]
        return "\n".join(out)

    for f in sort_findings(findings):
        out += [
            f"## {f.check} -- {f.title}", "",
            f"**Severity** {f.severity.value}  ",
            f"**Confidence** {f.confidence}  ",
            (f"**Related** {', '.join(f.taxonomy)}  "
             if f.taxonomy else ""),
            "",
            f.claim, "",
            "### evidence", "", "```", _fmt(f.evidence), "```", "",
        ]
        if f.remediation:
            out += ["### remediation", "", f.remediation, ""]
    return "\n".join(out)


def _fmt(obj, indent: int = 0) -> str:
    pad = " " * indent
    if isinstance(obj, dict):
        return "\n".join(
            f"{pad}{k}:" + ("\n" + _fmt(v, indent + 2)
                            if isinstance(v, (dict, list))
                            else f" {v}")
            for k, v in obj.items())
    if isinstance(obj, list):
        return "\n".join(
            (_fmt(v, indent + 2) if isinstance(v, (dict, list))
             else f"{pad}- {v}") for v in obj)
    return f"{pad}{obj}"
