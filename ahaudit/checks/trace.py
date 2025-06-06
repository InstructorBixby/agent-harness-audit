"""AHA-004: trace completeness.

Not a preventive control, and the precondition for every other answer.
Without the trace, an injection that fired is a conversation about
model behaviour, and a finding is unprovable after the fact.

The five fields are not interchangeable. Most harnesses record the
proposed action and the result, which is enough to see that something
happened and not enough to attribute it. Provenance is the one that is
always missing and the one that turns "the model did something odd"
into "this document caused this call".
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness

WEIGHT = {
    "records_executed_arguments": (
        Severity.HIGH,
        "Executed arguments are not recorded, so a call that carried "
        "data outward cannot be distinguished from a benign one, and "
        "an exfiltration finding is unprovable after the fact.",
        ["TC-001", "EX-003", "DEF-012"]),
    "records_context_provenance": (
        Severity.HIGH,
        "The provenance of the context items that influenced a call is "
        "not recorded, so an incident cannot be attributed to the "
        "content that caused it.",
        ["DEF-007", "DEF-012", "AG-002"]),
    "records_authz_decision": (
        Severity.MEDIUM,
        "The authorisation decision is not recorded, so there is no "
        "evidence that a control engaged, or that it did not.",
        ["DEF-012"]),
    "records_agent_identity": (
        Severity.MEDIUM,
        "Actions are not attributed to the agent that took them, so "
        "sub-agent behaviour is indistinguishable from the parent's.",
        ["AG-005", "DEF-012"]),
    "records_proposed_action": (
        Severity.LOW,
        "The proposed action is not recorded separately from the "
        "executed one, so a call that was modified between proposal "
        "and execution leaves no trace of the difference.",
        ["DEF-012"]),
    "records_result": (
        Severity.LOW,
        "Tool results are not recorded, so the content that re-entered "
        "the context cannot be reviewed.",
        ["IPI-011", "DEF-012"]),
}


@register("AHA-004", "Trace cannot reconstruct a decision")
def check(harness: Harness) -> list[Finding]:
    t = harness.trace
    out: list[Finding] = []
    for field, (severity, claim, taxonomy) in WEIGHT.items():
        if getattr(t, field) is False:
            out.append(Finding(
                check="AHA-004",
                title=f"Trace omits {field.removeprefix('records_').replace('_', ' ')}",
                severity=severity,
                claim=claim,
                evidence={"trace": {field: False,
                                    "missing": t.missing}},
                remediation="Record, per action: proposed action, "
                            "provenance of the influencing context, "
                            "authorisation decision, executed "
                            "arguments, result, and the acting agent.",
                taxonomy=taxonomy,
            ))
    return out
