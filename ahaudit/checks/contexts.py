"""AHA-002: what each context holds.

The composition check at the context level. A context that reads
third-party-writable content and holds a tool with reach is a confused
deputy waiting for a document; add private data and it is an
exfiltration pipeline with no vulnerability in any component.

Reported per context, never per application. A harness commonly has one
context that is fine and one that holds everything, and an
application-level answer hides that.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness, Reach

REACHY = (Reach.LOCAL_WRITE, Reach.INTERNAL_NETWORK,
          Reach.EXTERNAL_NETWORK, Reach.EXECUTE)


@register("AHA-002", "Untrusted content and privileged tools in one context")
def check(harness: Harness) -> list[Finding]:
    out: list[Finding] = []
    for ctx in harness.contexts:
        untrusted = ctx.untrusted_sources()
        if not untrusted:
            continue
        tools = harness.tools_in(ctx)
        reachy = [t for t in tools if t.max_reach in REACHY]
        egress = [t for t in tools if t.egress]
        if not reachy:
            continue

        severity = Severity.HIGH
        claim = (f"Context {ctx.name!r} is assembled from "
                 f"{', '.join(s.name for s in untrusted)} and holds "
                 f"{', '.join(t.name for t in reachy)}, so content "
                 f"from those sources can steer a privileged action.")
        if ctx.holds_private_data and egress:
            severity = Severity.CRITICAL
            claim += (" It also holds data the requesting principal "
                      "could not otherwise obtain, and "
                      f"{', '.join(t.name for t in egress)} can move "
                      "bytes outward, so the three properties needed "
                      "for exfiltration are present in one context.")

        out.append(Finding(
            check="AHA-002",
            title=f"Context {ctx.name!r} mixes untrusted content with "
                  f"capability",
            severity=severity,
            claim=claim,
            evidence={
                "context": ctx.name,
                "untrusted_sources": [
                    {"name": s.name, "trust": s.trust.value,
                     "third_party_writable": s.third_party_writable}
                    for s in untrusted],
                "tools": [{"name": t.name,
                           "reach": t.max_reach.value,
                           "egress": t.egress} for t in reachy],
                "holds_private_data": ctx.holds_private_data,
            },
            remediation="Split the context, or remove one of the three "
                        "properties from it. Removing egress is "
                        "usually cheapest.",
            taxonomy=["AG-001", "AG-007", "IPI-001", "TC-001"],
        ))
    return out
