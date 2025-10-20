"""Load a harness description from YAML.

The manifest is the point of the tool as much as the checks are:
somebody has to write down the authority model, and on every engagement
so far the act of writing it down has produced findings before the tool
ran. So the loader is strict and the error messages are written for
whoever is filling it in, not for me.

Unknown keys are an error, not a shrug. A misspelled section that is
silently ignored produces a clean report about a harness nobody
described.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from ahaudit.model_glue import definition_set
from ahaudit.model import (Approval, Authorisation, AuthzSubject,
                           AuthzTiming, Budget, Capability,
                           Concurrency, Context, ContextSource,
                           Delegation, Harness, Principal, Reach, Tool,
                           Trace, Trust)


class ManifestError(ValueError):
    pass


SECTIONS = {"name", "notes", "principals", "tools", "contexts",
            "authorisation", "delegation", "trace", "approval",
            "budget", "concurrency", "definitions"}


def _enum(cls, value, where: str):
    try:
        return cls(value)
    except ValueError:
        allowed = ", ".join(m.value for m in cls)
        raise ManifestError(
            f"{where}: {value!r} is not valid; expected one of "
            f"{allowed}") from None


def _only_known(d: dict, known: set[str], where: str) -> dict:
    extra = sorted(set(d) - known)
    if extra:
        raise ManifestError(
            f"{where}: unknown key(s) {', '.join(extra)}; known keys "
            f"are {', '.join(sorted(known))}")
    return d


def _capability(d: dict, where: str) -> Capability:
    _only_known(d, {"name", "reach", "egress", "sensitive_read"},
                where)
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
    _only_known(d, {"name", "capabilities", "runs_as",
                    "definition_source", "requires_approval"}, where)
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
    _only_known(d, {"name", "sources", "tools", "holds_private_data"},
                where)
    sources = []
    for s in d.get("sources", []):
        _only_known(s, {"name", "trust", "third_party_writable"},
                    f"{where}.sources")
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


def _flags(cls, raw: dict, where: str):
    known = set(cls.__slots__)
    _only_known(raw, known, where)
    return cls(**{k: bool(v) for k, v in raw.items()})


def load(path: str | Path) -> Harness:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ManifestError("manifest must be a mapping")
    return from_dict(raw)


def from_dict(raw: dict) -> Harness:
    if "harness" not in raw:
        raise ManifestError("manifest needs a top-level 'harness' key")
    h = _only_known(raw["harness"], SECTIONS, "harness")

    authz = _only_known(h.get("authorisation", {}),
                        set(Authorisation.__slots__), "authorisation")
    approval = _only_known(h.get("approval", {}),
                           set(Approval.__slots__), "approval")
    budget = _only_known(h.get("budget", {}) or {},
                         set(Budget.__slots__), "budget")

    harness = Harness(
        name=h.get("name", "unnamed"),
        tools=[_tool(t) for t in h.get("tools", [])],
        contexts=[_context(c) for c in h.get("contexts", [])],
        principals=[Principal(p.get("name", "unnamed"),
                              p.get("kind", "user"))
                    for p in h.get("principals", [])],
        authorisation=Authorisation(
            subject=_enum(AuthzSubject, authz.get("subject", "none"),
                          "authorisation.subject"),
            timing=_enum(AuthzTiming, authz.get("timing", "never"),
                         "authorisation.timing"),
            halts_on_denial=bool(authz.get("halts_on_denial", False)),
            enforced_by=authz.get("enforced_by", "unknown"),
        ),
        delegation=_flags(Delegation, h.get("delegation", {}),
                          "delegation"),
        trace=_flags(Trace, h.get("trace", {}), "trace"),
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
        concurrency=_flags(Concurrency, h.get("concurrency", {}),
                           "concurrency"),
        definitions=definition_set(h.get("definitions")),
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
