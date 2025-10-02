"""AHA-009: definition pinning and re-reading."""
from __future__ import annotations

from ahaudit.checks import register
from ahaudit.findings import Finding, Severity
from ahaudit.model import Harness


@register("AHA-009", "Tool definitions not pinned after approval")
def check(harness: Harness) -> list[Finding]:
    ds = harness.definitions
    if ds is None or not ds.definitions:
        return []

    out: list[Finding] = []
    third_party = [d for d in ds.definitions
                   if not d.source.operator_controlled]

    if third_party and not ds.pinned:
        out.append(Finding(
            check="AHA-009",
            title="Definitions from a third party are not pinned",
            severity=Severity.HIGH,
            claim="Tool definitions supplied by a party other than the "
                  "operator are not pinned to an approved digest, so "
                  "the text in every request can change without "
                  "anyone re-approving it.",
            evidence={"tools": [
                {"name": d.name, "server": d.server,
                 "source": d.source.value} for d in third_party],
                "pinned": False},
            remediation="Hash the approved definition set and refuse "
                        "to run a set that does not match; re-approve "
                        "on change, showing a diff.",
            taxonomy=["TC-003", "TC-004", "TC-008"],
        ))

    if ds.drifted:
        out.append(Finding(
            check="AHA-009",
            title="Live definitions do not match the pinned digest",
            severity=Severity.CRITICAL,
            claim="The definitions currently loaded differ from the "
                  "ones that were approved.",
            evidence={"pinned_digest": ds.pinned_digest,
                      "live_digest": ds.digest()},
            remediation="Stop, diff the definitions, and find out who "
                        "changed them.",
            taxonomy=["TC-008"],
            confidence="observed",
        ))

    if third_party and (ds.reread_on_reconnect
                        or ds.reread_on_notification):
        triggers = [name for name, flag in
                    (("reconnect", ds.reread_on_reconnect),
                     ("server notification", ds.reread_on_notification))
                    if flag]
        out.append(Finding(
            check="AHA-009",
            title="Definitions re-read without re-approval",
            severity=Severity.MEDIUM if ds.pinned else Severity.HIGH,
            claim=f"Definitions are re-read on "
                  f"{' and '.join(triggers)}, so the set in effect is "
                  f"not necessarily the set anybody reviewed.",
            evidence={"triggers": triggers,
                      "pinned": ds.pinned},
            remediation="Re-approval on every change, with a diff. "
                        "Pinning without re-approval just moves the "
                        "failure to a startup error.",
            taxonomy=["TC-008"],
        ))

    if ds.approval_scope != "definition" and third_party:
        out.append(Finding(
            check="AHA-009",
            title=f"Approval is scoped to the {ds.approval_scope}",
            severity=Severity.MEDIUM,
            claim=f"Approval is recorded per {ds.approval_scope} "
                  f"rather than per definition, so a changed "
                  f"description inherits an approval granted for "
                  f"different text.",
            evidence={"approval_scope": ds.approval_scope},
            remediation="Record approval against the definition "
                        "digest.",
            taxonomy=["TC-008", "TC-003"],
        ))

    if not ds.shows_description_at_approval and third_party:
        out.append(Finding(
            check="AHA-009",
            title="Approval UI does not show the description",
            severity=Severity.MEDIUM,
            claim="The operator approves a tool by name without being "
                  "shown the description and parameter text, which is "
                  "the part that reaches the model in every request.",
            evidence={"shows_description_at_approval": False},
            remediation="Show the full definition text at approval, "
                        "and the diff at re-approval.",
            taxonomy=["TC-003", "TC-004"],
        ))

    return out
