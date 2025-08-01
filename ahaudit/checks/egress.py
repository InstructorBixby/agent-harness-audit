"""AHA-007: egress.

The leg of the trifecta that is cheapest to remove and most often
missed, because the tools that provide it are rarely called egress. A
search tool, a telemetry client, an error reporter, a link unfurler, a
feature-flag lookup: every one of them moves bytes to a party the
requesting principal does not control.

So this check does two things. It reports egress tools sharing a
context with sensitive reads (which AHA-006 covers from the pair side),
and -- more usefully -- it flags tools whose declared reach is external
but whose egress flag is false, because that combination is almost
always a manifest the author has not thought about rather than a tool
that genuinely cannot leak.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness, Reach

# Tool names that are egress in practice whatever the manifest says.
SUSPECT_NAMES = ("search", "telemetry", "metric", "log", "report",
                 "unfurl", "preview", "analytics", "flag", "trace",
                 "webhook", "notify")


@register("AHA-007", "Egress paths not accounted for")
def check(harness: Harness) -> list[Finding]:
    out: list[Finding] = []

    unflagged = [t for t in harness.tools
                 if t.max_reach is Reach.EXTERNAL_NETWORK
                 and not t.egress]
    if unflagged:
        out.append(Finding(
            check="AHA-007",
            title="External-network tools not declared as egress",
            severity=Severity.MEDIUM,
            claim="These tools reach the external network and are "
                  "declared as not moving data outward, which is true "
                  "only if their arguments cannot carry data. For a "
                  "free-text argument it is not true.",
            evidence={"tools": [
                {"name": t.name,
                 "capabilities": [c.name for c in t.capabilities]}
                for t in unflagged]},
            remediation="Set egress on any tool whose arguments can "
                        "carry data to a party the principal does not "
                        "control, then constrain those arguments.",
            taxonomy=["EX-003", "DEF-011"],
            confidence="inferred",
        ))

    suspects = [t for t in harness.tools
                if not t.egress
                and any(s in t.name.lower() for s in SUSPECT_NAMES)]
    if suspects:
        out.append(Finding(
            check="AHA-007",
            title="Quiet egress tools not declared as egress",
            severity=Severity.LOW,
            claim="These tools are named like the ones that are never "
                  "on the list when I ask which tools can send data "
                  "out, and they are declared as not egressing. Worth "
                  "confirming rather than assuming.",
            evidence={"tools": [t.name for t in suspects]},
            remediation="Confirm per tool where the bytes go. Search, "
                        "telemetry, logging, error reporting and link "
                        "unfurling are egress if the destination is "
                        "not under the principal's control.",
            taxonomy=["EX-003", "DEF-011"],
            confidence="inferred",
        ))

    no_egress = [t for t in harness.tools if t.egress]
    if not no_egress and any(
            c.holds_private_data for c in harness.contexts):
        out.append(Finding(
            check="AHA-007",
            title="No egress declared anywhere",
            severity=Severity.INFO,
            claim="No tool is declared as egress. If that is accurate "
                  "the exfiltration half of this tool's threat model "
                  "does not apply, which is worth stating explicitly "
                  "in a report rather than leaving implied.",
            evidence={"tools": len(harness.tools)},
            remediation="Confirm, including the rendered output path: "
                        "a markdown image is an egress channel that no "
                        "tool manifest mentions.",
            taxonomy=["EX-001", "DEF-011"],
            confidence="inferred",
        ))

    return out
