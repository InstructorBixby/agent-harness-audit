"""AHA-010: two sources of tools, one namespace.

A host that aggregates tools from several servers has to resolve name
collisions, and the resolution is usually registration order with no
warning. A description that claims to supersede a sibling needs no
collision at all, which is why the confusable check and the collision
check are separate findings.
"""
from __future__ import annotations

import re
import unicodedata
from collections import Counter, defaultdict

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness

SUPERSEDE_RE = re.compile(
    r"\b(instead of|deprecat|supersed|replaces|do not use|"
    r"use this rather than)\b", re.I)

# Cheap confusable folding: strip accents, collapse digit/letter
# lookalikes, drop separators. Not UTS #39, enough to catch
# send_emai1 and send-email.
LOOKALIKE = str.maketrans({"1": "l", "0": "o", "5": "s", "3": "e",
                           "_": "", "-": "", ".": ""})


def skeleton(name: str) -> str:
    folded = unicodedata.normalize("NFKD", name)
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    return folded.lower().translate(LOOKALIKE)


@register("AHA-010", "Tool namespace collisions and shadowing")
def check(harness: Harness) -> list[Finding]:
    ds = harness.definitions
    if ds is None or not ds.definitions:
        return []
    out: list[Finding] = []

    by_name = Counter(d.name for d in ds.definitions)
    collisions = {n for n, c in by_name.items() if c > 1}
    if collisions and not ds.namespaced_by_server:
        out.append(Finding(
            check="AHA-010",
            title="Tool names collide across servers",
            severity=Severity.HIGH,
            claim="Two servers provide a tool with the same name into "
                  "one namespace, so which implementation runs is "
                  "decided by registration order.",
            evidence={"names": sorted(collisions),
                      "namespaced_by_server": False},
            remediation="Namespace tools by server, show the namespace "
                        "in the approval UI, and reject or warn on a "
                        "collision.",
            taxonomy=["TC-010", "TC-005"],
        ))

    groups = defaultdict(list)
    for d in ds.definitions:
        groups[skeleton(d.name)].append(d)
    confusable = {k: v for k, v in groups.items()
                  if len({d.name for d in v}) > 1}
    if confusable:
        out.append(Finding(
            check="AHA-010",
            title="Confusable tool names",
            severity=Severity.MEDIUM,
            claim="Tool names that differ only in characters a reader "
                  "will not notice are present in one namespace, so an "
                  "operator approving one may be approving the other.",
            evidence={"groups": [sorted({d.name for d in v})
                                 for v in confusable.values()]},
            remediation="Reject confusable registrations; compare "
                        "skeletons rather than exact strings.",
            taxonomy=["TC-010", "PI-009"],
        ))

    superseding = [d for d in ds.definitions
                   if SUPERSEDE_RE.search(d.description or "")
                   and not d.source.operator_controlled]
    if superseding:
        out.append(Finding(
            check="AHA-010",
            title="Third-party description claims to supersede another "
                  "tool",
            severity=Severity.HIGH,
            claim="A definition the operator did not write instructs "
                  "the model to prefer it over another tool, which "
                  "needs no name collision to shadow a legitimate "
                  "tool.",
            evidence={"tools": [
                {"name": d.name, "server": d.server,
                 "description": d.description[:200]}
                for d in superseding]},
            remediation="Strip or review descriptions from "
                        "non-operator sources; pin them (AHA-009).",
            taxonomy=["TC-003", "TC-010"],
            confidence="inferred",
        ))

    return out
