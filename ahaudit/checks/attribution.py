"""AHA-001: what principal is a tool call attributed to.

The first check written, because it is the first question I ask on an
engagement and because the answer has been wrong in every harness I
have looked at so far.

A tool that authenticates as a service identity makes every
authorisation decision about the wrong subject. The model's choice of
arguments then becomes the access-control boundary, which means an
ordinary confusion -- not even an attack -- crosses it.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import AuthzSubject, AuthzTiming, Harness


@register("AHA-001", "Tool calls not attributed to the requesting principal")
def check(harness: Harness) -> list[Finding]:
    out: list[Finding] = []
    authz = harness.authorisation

    if authz.subject in (AuthzSubject.NONE,):
        out.append(Finding(
            check="AHA-001",
            title="No authorisation check between intent and execution",
            severity=Severity.CRITICAL,
            claim="The harness executes tool calls without evaluating "
                  "any entitlement, so the model's output is the only "
                  "thing deciding what happens.",
            evidence={"authorisation": {
                "subject": authz.subject.value,
                "timing": authz.timing.value,
                "enforced_by": authz.enforced_by}},
            remediation="Authorise every call against the requesting "
                        "principal at execution time.",
            taxonomy=["TC-001", "TC-009", "AG-001"],
        ))
        return out

    if authz.subject == AuthzSubject.SERVICE_IDENTITY:
        out.append(Finding(
            check="AHA-001",
            title="Tool calls authorised as a service identity",
            severity=Severity.HIGH,
            claim="Authorisation evaluates the harness's own identity "
                  "rather than the requesting principal's, so any "
                  "data any user may reach is reachable by every user.",
            evidence={"authorisation": {
                "subject": authz.subject.value,
                "timing": authz.timing.value}},
            remediation="Propagate the requesting principal and "
                        "authorise in the data layer.",
            taxonomy=["TC-009"],
        ))

    if authz.subject == AuthzSubject.MODEL_SUPPLIED:
        out.append(Finding(
            check="AHA-001",
            title="Authorisation subject supplied by the model",
            severity=Severity.CRITICAL,
            claim="The principal or tenant the check evaluates is an "
                  "argument the model chose, so the access-control "
                  "boundary is the model's argument selection.",
            evidence={"authorisation": {
                "subject": authz.subject.value}},
            remediation="Never accept the subject from model output. "
                        "Take it from the authenticated request.",
            taxonomy=["TC-009", "OUT-007"],
        ))

    if authz.timing in (AuthzTiming.PER_SESSION, AuthzTiming.AT_STARTUP):
        out.append(Finding(
            check="AHA-001",
            title="Authority granted per session, spent per action",
            severity=Severity.HIGH,
            claim=f"Entitlement is evaluated {authz.timing.value}, so "
                  f"an unbounded number of later actions run on one "
                  f"decision made before any content was read.",
            evidence={"authorisation": {"timing": authz.timing.value}},
            remediation="Move the check to per-call.",
            taxonomy=["AG-001"],
        ))

    return out
