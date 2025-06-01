"""AHA-003: delegation.

A boundary enforced at the top level and re-granted one level down is
not a boundary. Delegation is implemented as "same client, new
conversation" often enough that the default assumption has to be that
everything is inherited, and the manifest's defaults say so.

Approval inheritance is called out separately because it voids a
control the operator believes they have, which is worse than never
having had it.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness


@register("AHA-003", "Sub-agents inherit authority without attenuation")
def check(harness: Harness) -> list[Finding]:
    d = harness.delegation
    if not d.enabled:
        return []

    out: list[Finding] = []

    if not d.attenuates and (d.inherits_tools or d.inherits_credentials):
        out.append(Finding(
            check="AHA-003",
            title="Delegation does not attenuate authority",
            severity=Severity.HIGH,
            claim="A sub-agent receives the parent's authority whole, "
                  "so a child spawned to read untrusted content holds "
                  "every tool the parent held.",
            evidence={"delegation": {
                "inherits_tools": d.inherits_tools,
                "inherits_credentials": d.inherits_credentials,
                "attenuates": d.attenuates}},
            remediation="Grant a child a subset, constructed for its "
                        "task, rather than passing the parent's tool "
                        "set and client.",
            taxonomy=["AG-005"],
        ))

    if d.inherits_approvals:
        out.append(Finding(
            check="AHA-003",
            title="Approval state inherited by sub-agents",
            severity=Severity.HIGH,
            claim="An approval granted for one action in one context "
                  "is carried into a child, so a child acting on "
                  "untrusted content can take a privileged action "
                  "without a human seeing it.",
            evidence={"delegation": {
                "inherits_approvals": True},
                "approval": {"enabled": harness.approval.enabled}},
            remediation="Approvals are per action and per principal. "
                        "Never inherited.",
            taxonomy=["AG-005", "TC-006", "DEF-006"],
        ))

    if d.inherits_context:
        out.append(Finding(
            check="AHA-003",
            title="Parent context inherited by sub-agents",
            severity=Severity.MEDIUM,
            claim="A child receives the parent's context, so untrusted "
                  "content read by the parent is present in every "
                  "child, and private data in the parent is present in "
                  "children that did not need it.",
            evidence={"delegation": {"inherits_context": True}},
            remediation="Pass the sub-task, not the transcript. Where "
                        "background is needed, pass a value the child "
                        "cannot act on.",
            taxonomy=["AG-005", "AG-002"],
        ))

    return out
