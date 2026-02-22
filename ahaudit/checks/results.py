"""AHA-013: results and errors as an input channel.

A tool result re-entering the context is text from whoever controls the
tool's data, arriving in a position of implicit trust -- it is what the
harness asked for, and it is usually formatted like a system notice.

Error strings are the forgotten half. A remote service that controls
its own error text controls text in the context, and error paths are
where the formatting discipline goes to die.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness, Reach, Trust

REACHY = (Reach.LOCAL_WRITE, Reach.INTERNAL_NETWORK,
          Reach.EXTERNAL_NETWORK, Reach.EXECUTE)


@register("AHA-013", "Tool results re-enter the context unmarked")
def check(harness: Harness) -> list[Finding]:
    out: list[Finding] = []
    for ctx in harness.contexts:
        sources = {s.trust for s in ctx.sources}
        if Trust.TOOL_RESULT not in sources:
            continue
        tools = harness.tools_in(ctx)
        reachy = [t for t in tools if t.max_reach in REACHY]
        if not reachy:
            continue
        marked = harness.trace.records_context_provenance
        out.append(Finding(
            check="AHA-013",
            title=f"Tool results re-enter context {ctx.name!r} "
                  f"alongside capability",
            severity=Severity.MEDIUM if marked else Severity.HIGH,
            claim="Results from tools that read external data re-enter "
                  "this context, so every tool that reads is an "
                  "injection path into every tool that acts.",
            evidence={"context": ctx.name,
                      "tools": [t.name for t in reachy],
                      "provenance_recorded": marked},
            remediation="Structure and truncate results, mark their "
                        "provenance, and do not feed raw tool error "
                        "strings back into the context.",
            taxonomy=["IPI-011", "AG-001", "TC-001"],
        ))
    return out
