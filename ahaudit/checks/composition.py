"""AHA-006: composition.

Authorisation is per call. Capability is compositional. A read of
something sensitive plus an egress is exfiltration; neither call is
remarkable on its own and a checker that looks at one call at a time
sees nothing wrong.

So this check enumerates the pairs. The matrix is small enough to do by
hand -- which is the point: nobody does, and it takes a few lines of
code to do it for them.
"""
from __future__ import annotations

from itertools import product

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness, Reach


@register("AHA-006", "Tool pairs compose into an unauthorised capability")
def check(harness: Harness) -> list[Finding]:
    out: list[Finding] = []
    for ctx in harness.contexts:
        tools = harness.tools_in(ctx)
        readers = [t for t in tools
                   if t.sensitive_read
                   or t.max_reach in (Reach.LOCAL_READ,)]
        egress = [t for t in tools if t.egress]
        pairs = [(r, e) for r, e in product(readers, egress)
                 if r.name != e.name]
        if not pairs:
            continue
        out.append(Finding(
            check="AHA-006",
            title=f"Read-then-send pairs available in context "
                  f"{ctx.name!r}",
            severity=Severity.HIGH,
            claim="Each call is individually authorised and the "
                  "composition is not: a tool that reads sensitive "
                  "data and a tool that can send data outward are "
                  "available in the same context, which is "
                  "exfiltration in two authorised steps.",
            evidence={"context": ctx.name,
                      "pairs": [[r.name, e.name] for r, e in pairs]},
            remediation="Taint-track data from sensitive sources and "
                        "refuse to pass it to an egress argument; or "
                        "do not grant read-sensitive and "
                        "write-external in one context.",
            taxonomy=["TC-007", "EX-003", "AG-007"],
        ))

        writers = [t for t in tools
                   if t.max_reach is Reach.LOCAL_WRITE]
        executors = [t for t in tools if t.max_reach is Reach.EXECUTE]
        wx = [(w, x) for w, x in product(writers, executors)
              if w.name != x.name]
        if wx:
            out.append(Finding(
                check="AHA-006",
                title=f"Write-then-execute pairs available in context "
                      f"{ctx.name!r}",
                severity=Severity.CRITICAL,
                claim="A tool that writes to the filesystem and a tool "
                      "that executes are available in the same "
                      "context, which composes into arbitrary code "
                      "execution in two authorised steps.",
                evidence={"context": ctx.name,
                          "pairs": [[w.name, x.name] for w, x in wx]},
                remediation="Separate the contexts, confine the write "
                            "root away from anything executable, and "
                            "deny writes to anything the harness "
                            "itself reads.",
                taxonomy=["TC-007", "OUT-003", "OUT-005", "OUT-008"],
            ))
    return out
