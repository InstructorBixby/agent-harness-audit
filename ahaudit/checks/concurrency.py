"""AHA-011: shared state between concurrent runs.

Harnesses are built single-user and deployed multi-user. The shared
objects are the ones that were expensive to create: a browser with
cookies, a container, a checkout directory, an embedding cache, a
long-lived client.

The injection version is the sharp one: a hostile task writes a file
that a concurrent benign task reads, which is an indirect injection
with the attacker's own run as the delivery mechanism and no retrieval
corpus needed at all.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness

WEIGHT = {
    "workspace": (Severity.HIGH,
                  "a concurrent task can write a file that another "
                  "task reads, which is an injection channel with no "
                  "corpus involved, and can read another task's "
                  "artefacts"),
    "browser_profile": (Severity.CRITICAL,
                        "cookies and authenticated sessions are shared "
                        "between tasks, so one principal's task acts "
                        "as another principal"),
    "memory_store": (Severity.HIGH,
                     "persisted notes from one task are read back by "
                     "another, which makes a one-shot injection "
                     "durable and cross-principal"),
    "cache": (Severity.MEDIUM,
              "derived artefacts are reused across tasks, so content "
              "crosses between them"),
}


@register("AHA-011", "State shared between concurrent runs")
def check(harness: Harness) -> list[Finding]:
    c = harness.concurrency
    out: list[Finding] = []
    for name in c.shared:
        severity, why = WEIGHT[name]
        out.append(Finding(
            check="AHA-011",
            title=f"Shared {name.replace('_', ' ')} between runs",
            severity=severity,
            claim=f"Concurrent tasks share the {name.replace('_', ' ')}: "
                  f"{why}.",
            evidence={"concurrency": {name: True,
                                      "shared": c.shared}},
            remediation="Per-run workspace, container and browser "
                        "profile. Startup cost is the price.",
            taxonomy=["AG-008", "DL-002"],
        ))

    if c.cache and not c.cache_keyed_by_principal:
        out.append(Finding(
            check="AHA-011",
            title="Cache not keyed by principal",
            severity=Severity.HIGH,
            claim="A shared cache whose key has no principal component "
                  "serves one principal's derived content to another.",
            evidence={"concurrency": {
                "cache": True, "cache_keyed_by_principal": False}},
            remediation="Principal or tenant in every cache key. "
                        "Measure the hit-rate cost and pay it.",
            taxonomy=["DL-005", "AG-008"],
        ))

    return out
