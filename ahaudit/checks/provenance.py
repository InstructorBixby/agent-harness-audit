"""AHA-012: provenance as a fact the code can act on.

Two different things get called provenance and conflating them is why
this gets dismissed:

- a *label in the prompt* telling the model that what follows is
  untrusted. Advisory, reduces rates, forgeable by whoever writes the
  content.
- a *fact available to the harness*: this context item came from this
  source, and an authorisation decision can read it.

The second is a control and is almost always missing, because the
context is assembled as a string. This check is about the second.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness, Reach

REACHY = (Reach.LOCAL_WRITE, Reach.INTERNAL_NETWORK,
          Reach.EXTERNAL_NETWORK, Reach.EXECUTE)


@register("AHA-012", "Provenance not available to authorisation")
def check(harness: Harness) -> list[Finding]:
    # If nothing untrusted reaches a context with capability, there is
    # nothing for provenance to gate and the finding would be noise.
    exposed = [c for c in harness.contexts
               if c.reads_untrusted
               and any(t.max_reach in REACHY
                       for t in harness.tools_in(c))]
    if not exposed:
        return []

    out: list[Finding] = []
    if not harness.trace.records_context_provenance:
        out.append(Finding(
            check="AHA-012",
            title="Context provenance is not recorded",
            severity=Severity.HIGH,
            claim="The harness does not record which context items "
                  "influenced an action, so it cannot gate a "
                  "privileged call on the presence of untrusted "
                  "content and cannot attribute an incident to the "
                  "content that caused it.",
            evidence={"contexts": [c.name for c in exposed],
                      "trace": {"records_context_provenance": False}},
            remediation="Assemble the context as items with sources, "
                        "not as a string. Then an authorisation "
                        "decision can read the source, and the trace "
                        "can name it.",
            taxonomy=["DEF-007", "DEF-012", "AG-001"],
        ))

    if harness.authorisation.enforced_by == "unknown":
        out.append(Finding(
            check="AHA-012",
            title="Authorisation enforcement point not identified",
            severity=Severity.MEDIUM,
            claim="Nobody could say where the authorisation decision "
                  "is made, which in every instance so far has meant "
                  "it is made in more than one place or in none.",
            evidence={"authorisation": {"enforced_by": "unknown"}},
            remediation="Name the function. If it cannot be named, "
                        "that is the finding.",
            taxonomy=["DEF-012"],
            confidence="inferred",
        ))

    return out
