"""AHA-015: model output written into state the harness trusts.

The composition that turns an incident into a condition. Model output
written somewhere the system reads back as configuration -- a rules
file, a memory record, a routing decision, a cached policy -- makes a
one-shot injection persistent.

The model does not carry a general "stores" concept, so this reads the
two places it can see: a persisted memory store that concurrent runs
share, and a context source that is both third-party writable and
trusted as `retrieved` while a write-capable tool is in the same
context. The second pattern is how a workspace rules file gets
rewritten by the loop that reads it.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness, Reach, Trust


@register("AHA-015", "Write paths into state the harness reads back")
def check(harness: Harness) -> list[Finding]:
    out: list[Finding] = []
    writers_by_context = {
        c.name: [t.name for t in harness.tools_in(c)
                 if t.max_reach in (Reach.LOCAL_WRITE, Reach.EXECUTE)]
        for c in harness.contexts
    }

    for ctx in harness.contexts:
        writers = writers_by_context[ctx.name]
        if not writers:
            continue
        readback = [s.name for s in ctx.sources
                    if s.trust in (Trust.RETRIEVED,
                                   Trust.TOOL_DEFINITION)
                    and s.third_party_writable]
        if not readback:
            continue
        out.append(Finding(
            check="AHA-015",
            title=f"Context {ctx.name!r} can write to state it reads "
                  f"back",
            severity=Severity.HIGH,
            claim=f"{', '.join(writers)} can write, and this context "
                  f"reads {', '.join(readback)} back in later runs, so "
                  f"a single injection can persist by editing what the "
                  f"harness reads.",
            evidence={"context": ctx.name, "writers": writers,
                      "read_back": readback},
            remediation="Harness configuration lives outside anything "
                        "the loop can write. Structured, typed writes "
                        "only into anything read back as "
                        "configuration.",
            taxonomy=["AG-004", "OUT-008", "OUT-005"],
        ))

    if harness.concurrency.memory_store:
        out.append(Finding(
            check="AHA-015",
            title="Persistent memory shared between runs",
            severity=Severity.HIGH,
            claim="A memory store shared across runs is a corpus the "
                  "harness writes to itself and reads back with none "
                  "of the controls it would apply to someone else's "
                  "corpus, usually in a privileged position near the "
                  "system prompt.",
            evidence={"concurrency": {"memory_store": True}},
            remediation="Memory is untrusted input on read regardless "
                        "of who wrote it. Typed preference fields "
                        "rather than free text, scoped per principal, "
                        "visible and revocable by the user.",
            taxonomy=["AG-004", "DL-002"],
        ))

    return out
