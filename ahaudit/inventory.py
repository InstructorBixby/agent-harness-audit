"""The blast-radius inventory.

Not a check. The most useful artefact this tool produces, and the one
clients act on: every tool, what identity it runs as, what it reaches,
which contexts expose it, and the narrowest version that would still
work.

That last column is a human's job. The tool lays out the table and
leaves it empty, because a filled-in guess is worse than a blank the
engineer has to answer.
"""
from __future__ import annotations

from ahaudit.model import Harness, Reach

RISK_ORDER = {r: i for i, r in enumerate(Reach)}


def rows(harness: Harness) -> list[dict]:
    out = []
    for tool in harness.tools:
        exposed_in = [c.name for c in harness.contexts
                      if tool.name in c.tools]
        untrusted_in = [c.name for c in harness.contexts
                        if tool.name in c.tools and c.reads_untrusted]
        out.append({
            "tool": tool.name,
            "runs_as": tool.runs_as,
            "reach": tool.max_reach.value,
            "egress": tool.egress,
            "sensitive_read": tool.sensitive_read,
            "approval": tool.requires_approval,
            "contexts": exposed_in,
            "untrusted_contexts": untrusted_in,
        })
    # Reach, then egress, then exposure to untrusted content, then
    # name. The previous key stopped at egress, so two tools with the
    # same reach came out in declaration order and the committed sample
    # reports changed whenever a manifest was reordered.
    out.sort(key=lambda r: (-RISK_ORDER[Reach(r["reach"])],
                            not r["egress"],
                            -len(r["untrusted_contexts"]),
                            r["tool"]))
    return out


def markdown(harness: Harness) -> str:
    lines = [
        "## blast-radius inventory", "",
        "Ordered by reach, then by whether it can send data out, then "
        "by exposure to untrusted content. The last column is for the "
        "engineer who owns the tool, not for this tool to guess.", "",
        "| tool | runs as | reach | egress | sensitive read | approval "
        "| exposed to untrusted content | narrowest version that still "
        "works |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows(harness):
        lines.append(
            f"| `{r['tool']}` | {r['runs_as']} | {r['reach']} | "
            f"{'yes' if r['egress'] else 'no'} | "
            f"{'yes' if r['sensitive_read'] else 'no'} | "
            f"{'yes' if r['approval'] else 'no'} | "
            f"{', '.join(r['untrusted_contexts']) or '--'} |  |")
    lines += ["",
              "Tools nobody uses are the cheapest finding in any "
              "engagement. Ask for usage counts before the "
              "remediation meeting and bring them to it.", ""]
    return "\n".join(lines)
