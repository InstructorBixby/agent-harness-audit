"""AHA-005: approval integrity.

Three separable failures, all of which I have seen shipped:

1. the dialog text comes from the model, so the human consents to a
   sentence rather than to a call;
2. the model decides whether approval is needed, so injected text can
   clear the requirement;
3. fatigue -- a harness that asks about everything trains a reflex.

(3) is not fixable by making the dialog better. It is fixable only by
asking less often, which is why the count is part of the check.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness, Reach

FATIGUE_THRESHOLD = 10
CONSEQUENTIAL = (Reach.LOCAL_WRITE, Reach.EXTERNAL_NETWORK,
                 Reach.EXECUTE)


@register("AHA-005", "Approval is not a control")
def check(harness: Harness) -> list[Finding]:
    a = harness.approval
    out: list[Finding] = []

    gated = [t for t in harness.tools if t.requires_approval]
    risky = [t for t in harness.tools
             if t.max_reach in CONSEQUENTIAL or t.egress]

    if not a.enabled:
        if risky:
            out.append(Finding(
                check="AHA-005",
                title="No approval step for consequential tools",
                severity=Severity.MEDIUM,
                claim="Tools that write, execute or send data outward "
                      "are invoked with no human in the loop.",
                evidence={"tools": [t.name for t in risky]},
                remediation="Gate the few genuinely consequential "
                            "actions. Few, or fatigue eats the "
                            "control.",
                taxonomy=["DEF-006", "TC-001"],
            ))
        return out

    if not a.renders_structured_call:
        out.append(Finding(
            check="AHA-005",
            title="Approval dialog text produced by the model",
            severity=Severity.HIGH,
            claim="The text shown to the user is model output rather "
                  "than a rendering of the structured call, so the "
                  "user can approve a sentence that does not describe "
                  "the pending action.",
            evidence={"approval": {
                "renders_structured_call": False}},
            remediation="Render the dialog from the tool name and the "
                        "actual arguments. Never from prose.",
            taxonomy=["TC-006", "OUT-006"],
        ))

    if a.model_can_skip:
        out.append(Finding(
            check="AHA-005",
            title="Approval requirement can be cleared by the model",
            severity=Severity.CRITICAL,
            claim="Whether approval is required is decided by a field "
                  "the model sets, so injected content can remove the "
                  "control.",
            evidence={"approval": {"model_can_skip": True}},
            remediation="The requirement is a policy decision outside "
                        "the model. Never a model-settable field.",
            taxonomy=["TC-006", "PI-004"],
        ))

    if a.prompts_per_session > FATIGUE_THRESHOLD:
        out.append(Finding(
            check="AHA-005",
            title="Approval fatigue",
            severity=Severity.MEDIUM,
            claim=f"An ordinary session produces about "
                  f"{a.prompts_per_session} approval prompts, which "
                  f"trains the user to approve without reading.",
            evidence={"approval": {
                "prompts_per_session": a.prompts_per_session,
                "threshold": FATIGUE_THRESHOLD}},
            remediation="Gate fewer actions. A control the user has "
                        "learned to click through is not a control.",
            taxonomy=["DEF-006"],
        ))

    ungated = [t.name for t in risky if t not in gated]
    if ungated:
        out.append(Finding(
            check="AHA-005",
            title="Consequential tools not gated",
            severity=Severity.MEDIUM,
            claim="Approval exists but is not required for tools that "
                  "write, execute or send data outward.",
            evidence={"ungated": ungated},
            remediation="Set requires_approval on the consequential "
                        "tools, and remove it from the rest.",
            taxonomy=["DEF-006", "DEF-005"],
        ))

    return out
