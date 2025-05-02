"""Load a harness description from YAML.

The manifest is the point of the tool as much as the checks are:
somebody has to write down the authority model, and on every engagement
so far the act of writing it down has produced findings before the tool
ran. So the loader is strict and the error messages are written for
whoever is filling it in, not for me.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from ahaudit.model import (Approval, Authorisation, AuthzSubject,
                           AuthzTiming, Budget, Capability, Context,
                           ContextSource, Delegation, Harness,
                           Principal, Reach, Tool, Trace, Trust)


class ManifestError(ValueError):
    pass


def _enum(cls, value, where: str):
    try:
        return cls(value)
    except ValueError:
        allowed = ", ".join(m.value for m in cls)
        raise ManifestError(
            f"{where}: {value!r} is not valid; expected one of "
            f"{allowed}") from None


def _capability(d: dict, where: str) -> Capability:
    if "reach" not in d:
        raise ManifestError(f"{where}: capability needs a 'reach'")
    return Capability(
        name=d.get("name", "unnamed"),
        reach=_enum(Reach, d["reach"], f"{where}.reach"),
        egress=bool(d.get("egress", False)),
        sensitive_read=bool(d.get("sensitive_read", False)),
    )


def _tool(d: dict) -> Tool:
    if "name" not in d:
        raise ManifestError("tools: every tool needs a 'name'")
    where = f"tools.{d['name']}"
    return Tool(
        name=d["name"],
        capabilities=[_capability(c, f"{where}.capabilities")
                      for c in d.get("capabilities", [])],
        runs_as=d.get("runs_as", "unknown"),
        definition_source=d.get("definition_source", "operator"),
        requires_approval=bool(d.get("requires_approval", False)),
    )


def _context(d: dict) -> Context:
    if "name" not in d:
        raise ManifestError("contexts: every context needs a 'name'")
    where = f"contexts.{d['name']}"
    sources = []
    for s in d.get("sources", []):
        if "trust" not in s:
            raise ManifestError(
                f"{where}: source {s.get('name', '?')!r} needs a "
                f"'trust'")
        sources.append(ContextSource(
            name=s.get("name", "unnamed"),
            trust=_enum(Trust, s["trust"], f"{where}.trust"),
            third_party_writable=bool(
                s.get("third_party_writable", False)),
        ))
    return Context(
        name=d["name"],
        sources=sources,
        tools=list(d.get("tools", [])),
        holds_private_data=bool(d.get("holds_private_data", False)),
    )


def load(path: str | Path) -> Harness:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ManifestError("manifest must be a mapping")
    return from_dict(raw)


def from_dict(raw: dict) -> Harness:
    if "harness" not in raw:
        raise ManifestError("manifest needs a top-level 'harness' key")
    h = raw["harness"]

    authz = h.get("authorisation", {})
    delegation = h.get("delegation", {})
    trace = h.get("trace", {})
    approval = h.get("approval", {})
    budget = h.get("budget", {})

    harness = Harness(
        name=h.get("name", "unnamed"),
        tools=[_tool(t) for t in h.get("tools", [])],
        contexts=[_context(c) for c in h.get("contexts", [])],
        principals=[Principal(p.get("name", "unnamed"),
                              p.get("kind", "user"))
                    for p in h.get("principals", [])],
        authorisation=Authorisation(
            subject=_enum(AuthzSubject,
                          authz.get("subject", "none"),
                          "authorisation.subject"),
            timing=_enum(AuthzTiming,
                         authz.get("timing", "never"),
                         "authorisation.timing"),
            halts_on_denial=bool(authz.get("halts_on_denial", False)),
            enforced_by=authz.get("enforced_by", "unknown"),
        ),
        delegation=Delegation(**{k: bool(v) for k, v in
                                 delegation.items()
                                 if k in vars(Delegation())}),
        trace=Trace(**{k: bool(v) for k, v in trace.items()
                       if k in vars(Trace())}),
        approval=Approval(
            enabled=bool(approval.get("enabled", False)),
            renders_structured_call=bool(
                approval.get("renders_structured_call", False)),
            model_can_skip=bool(approval.get("model_can_skip", False)),
            prompts_per_session=int(
                approval.get("prompts_per_session", 0)),
        ),
        budget=Budget(
            steps=budget.get("steps"),
            tool_calls=budget.get("tool_calls"),
            tokens=budget.get("tokens"),
            shared_across_delegates=bool(
                budget.get("shared_across_delegates", False)),
        ),
        notes=h.get("notes", ""),
    )

    known = {t.name for t in harness.tools}
    for ctx in harness.contexts:
        for name in ctx.tools:
            if name not in known:
                raise ManifestError(
                    f"contexts.{ctx.name}: tool {name!r} is not "
                    f"declared under 'tools'")
    return harness
