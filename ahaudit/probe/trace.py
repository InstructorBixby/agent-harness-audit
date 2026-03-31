"""Probe: does the trace contain what the manifest says it does.

The cheapest high-value thing in the whole tool. The manifest says the
harness records executed arguments; the trace from an ordinary task
says whether it does. The two disagree often enough that asking for one
trace has become the first thing I do.
"""
from __future__ import annotations

from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness
from ahaudit.probe import register

FIELD_KEYS = {
    "records_proposed_action": ("proposed", "proposed_action",
                                "intent"),
    "records_context_provenance": ("provenance", "context_provenance",
                                   "sources", "influenced_by"),
    "records_authz_decision": ("authz", "authorisation", "authorized",
                               "decision"),
    "records_executed_arguments": ("arguments", "args",
                                   "executed_arguments"),
    "records_result": ("result", "output"),
    "records_agent_identity": ("agent", "agent_id", "actor"),
}


def _events(artefact) -> list[dict]:
    if isinstance(artefact, list):
        return [e for e in artefact if isinstance(e, dict)]
    if isinstance(artefact, dict):
        for key in ("events", "steps", "trace", "actions"):
            if isinstance(artefact.get(key), list):
                return [e for e in artefact[key] if isinstance(e, dict)]
    return []


def present(events: list[dict], keys: tuple[str, ...]) -> bool:
    return any(any(k in e for k in keys) for e in events)


@register("PROBE-trace")
def check(harness: Harness, artefacts: dict) -> list[Finding]:
    artefact = artefacts.get("trace")
    if artefact is None:
        return []
    events = _events(artefact)
    if not events:
        return [Finding(
            check="AHA-004",
            title="Trace artefact contains no recognisable events",
            severity=Severity.MEDIUM,
            claim="The supplied trace could not be parsed into "
                  "per-action events, so nothing about it can be "
                  "verified -- which is itself worth knowing about a "
                  "trace that is meant to support an investigation.",
            evidence={"keys": sorted(artefact)[:10]
                      if isinstance(artefact, dict) else "list"},
            remediation="Emit one structured event per action.",
            taxonomy=["DEF-012"],
            confidence="observed",
        )]

    out: list[Finding] = []
    for field, keys in FIELD_KEYS.items():
        declared = getattr(harness.trace, field)
        observed = present(events, keys)
        if declared and not observed:
            nice = field.removeprefix("records_").replace("_", " ")
            out.append(Finding(
                check="AHA-004",
                title=f"Trace declares {nice} and does not record it",
                severity=Severity.HIGH,
                claim=f"The manifest says {nice} is recorded; no event "
                      f"in the supplied trace contains it.",
                evidence={"field": field,
                          "looked_for": list(keys),
                          "events": len(events)},
                remediation="Either record it or correct the manifest. "
                            "A manifest that overstates the trace "
                            "makes every other finding in this report "
                            "less reliable.",
                taxonomy=["DEF-012"],
                confidence="observed",
            ))
        elif observed and not declared:
            nice = field.removeprefix("records_").replace("_", " ")
            out.append(Finding(
                check="AHA-004",
                title=f"Trace records {nice} but the manifest says "
                      f"otherwise",
                severity=Severity.INFO,
                claim=f"The trace contains {nice}, which the manifest "
                      f"declares absent. Good news, and the manifest "
                      f"should say so.",
                evidence={"field": field, "events": len(events)},
                remediation="Update the manifest.",
                confidence="observed",
            ))
    return out
