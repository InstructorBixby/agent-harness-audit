"""AHA-008: budgets, and what happens when a control says no.

Two cheap properties that are absent in most harnesses and that cost
nothing to add:

- a bound on steps, calls and tokens, shared across delegates
- a denial that halts rather than one the loop retries past

The second is the sharper one. A loop that retries after an
authorisation failure will eventually find a phrasing that passes, and
the harness has turned a working control into a search problem.
"""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness


@register("AHA-008", "Unbounded loop or non-terminal denial")
def check(harness: Harness) -> list[Finding]:
    out: list[Finding] = []
    b = harness.budget

    missing = [name for name in ("steps", "tool_calls", "tokens")
               if getattr(b, name) is None]
    if missing:
        out.append(Finding(
            check="AHA-008",
            title="Loop is not bounded",
            severity=Severity.MEDIUM,
            claim=f"No limit is declared for {', '.join(missing)}, so "
                  f"content that makes the loop do more work -- a "
                  f"claimed pagination, a retry, a fan-out -- is "
                  f"bounded only by whatever times out first.",
            evidence={"budget": {
                "steps": b.steps, "tool_calls": b.tool_calls,
                "tokens": b.tokens}},
            remediation="Hard limits per task on steps, calls and "
                        "tokens, enforced by the harness, surfaced "
                        "when exhausted rather than silently "
                        "truncating.",
            taxonomy=["AG-003"],
        ))

    if harness.delegation.enabled and not b.shared_across_delegates:
        out.append(Finding(
            check="AHA-008",
            title="Budgets not shared across delegates",
            severity=Severity.MEDIUM,
            claim="Each sub-agent gets its own budget, so a fan-out "
                  "multiplies the total: a sensible per-agent limit "
                  "with no task-level limit still permits hundreds of "
                  "calls from one instruction.",
            evidence={"delegation": {"enabled": True},
                      "budget": {"shared_across_delegates": False}},
            remediation="One budget for the whole task, debited by "
                        "every agent in it.",
            taxonomy=["AG-003", "AG-005"],
        ))

    if not harness.authorisation.halts_on_denial:
        out.append(Finding(
            check="AHA-008",
            title="Authorisation denial does not halt the loop",
            severity=Severity.HIGH,
            claim="A denied call does not terminate the task, so the "
                  "loop can retry with different arguments until one "
                  "is permitted, which turns a working control into a "
                  "search problem.",
            evidence={"authorisation": {"halts_on_denial": False}},
            remediation="A denial halts the task and is surfaced to "
                        "the user. Retrying a denied privileged action "
                        "is never the right default.",
            taxonomy=["AG-001", "AG-003", "DEF-012"],
        ))

    return out
