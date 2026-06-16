"""AHA-014: argument surface.

A tool exposed to a model has its parameters turned into an untrusted
input surface, and nothing in the schema says so. A free-text string
parameter on a tool with reach is the widest version of that surface;
an enum or an integer is the narrowest.

Schema review is cheap and almost never done, and the fix is usually
"this was always meant to be an id", so this check earns its place by
producing findings people close.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness, Reach

REACHY = (Reach.LOCAL_WRITE, Reach.INTERNAL_NETWORK,
          Reach.EXTERNAL_NETWORK, Reach.EXECUTE)
NARROW = ("integer", "number", "boolean")


def _wide_params(parameters: dict) -> list[str]:
    wide = []
    for name, spec in (parameters or {}).items():
        if not isinstance(spec, dict):
            wide.append(name)
            continue
        if spec.get("enum"):
            continue
        if spec.get("type") in NARROW:
            continue
        if spec.get("type") in (None, "string", "object", "array"):
            wide.append(name)
    return wide


@register("AHA-014", "Free-text arguments on tools with reach")
def check(harness: Harness) -> list[Finding]:
    ds = harness.definitions
    if ds is None or not ds.definitions:
        return []

    by_name = {t.name: t for t in harness.tools}
    offenders = []
    for d in ds.definitions:
        tool = by_name.get(d.name)
        if tool is None:
            continue
        if tool.max_reach not in REACHY and not tool.egress:
            continue
        wide = _wide_params(d.parameters)
        if wide:
            offenders.append({"tool": d.name,
                              "reach": tool.max_reach.value,
                              "egress": tool.egress,
                              "parameters": wide})

    if not offenders:
        return []

    return [Finding(
        check="AHA-014",
        title="Free-text arguments on tools with reach",
        severity=Severity.MEDIUM,
        claim="These tools accept unconstrained string, object or "
              "array arguments and can write, execute or send data "
              "outward, so their parameters are an untrusted input "
              "surface as wide as the model's output.",
        evidence={"tools": offenders},
        remediation="Narrow the schema: enums over free strings, "
                    "integers over identifiers, no path or URL "
                    "parameters where an id will do. Then validate at "
                    "the tool boundary, because the parameters are now "
                    "a public API.",
        taxonomy=["TC-002", "EX-003", "OUT-004", "OUT-005"],
    )]
