"""Rendering findings."""
from __future__ import annotations

from collections import Counter

from ahaudit import inventory
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


def markdown(harness: Harness, findings: list[Finding], *,
             notes: list[str] | None = None,
             with_inventory: bool = True) -> str:
    out = [f"# Harness audit: {harness.name}", ""]
    counts = Counter(f.severity.value for f in findings)
    out += ["| severity | count |", "|---|---|"]
    for s in reversed(list(Severity)):
        out.append(f"| {s.value} | {counts.get(s.value, 0)} |")
    out.append("")

    if notes:
        out += ["## notes", ""]
        out += [f"- {n}" for n in notes]
        out.append("")

    if not findings:
        out += ["No findings. Note what that does and does not mean: "
                "every declared check is a question about the "
                "manifest, so a clean result means the declaration is "
                "sound, not that the implementation matches it.", ""]
    else:
        for f in sort_findings(findings):
            out += [
                f"## {f.check} -- {f.title}", "",
                f"**Severity** {f.severity.value}  ",
                f"**Confidence** {f.confidence}  ",
                (f"**Related** {', '.join(f.taxonomy)}  "
                 if f.taxonomy else ""),
                "",
                f.claim, "",
            ]
            if f.evidence:
                out += ["### evidence", "", "```", _fmt(f.evidence),
                        "```", ""]
            if f.remediation:
                out += ["### remediation", "", f.remediation, ""]

    if with_inventory:
        out.append(inventory.markdown(harness))

    if findings:
        out += ["## appendix: taxonomy cross-reference", "",
                "Ids are from llm-redteam-notes, so a structural "
                "finding here and a measured rate from promptfuzz go "
                "into a report as one argument rather than two.", "",
                "| check | related |", "|---|---|"]
        for f in sort_findings(findings):
            if f.taxonomy:
                out.append(f"| {f.check} | {', '.join(f.taxonomy)} |")
        out.append("")
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
