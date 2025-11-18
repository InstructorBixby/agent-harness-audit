"""Populate a definition set from something real.

Two sources, both optional and both producing `observed` findings
rather than `declared` ones:

1. a JSON file containing a tools/list response, which is what I
   usually get handed on an engagement;
2. a host's own configuration, where the tool definitions are
   vendored.

Deliberately does not speak to a server itself. Connecting to a client's
infrastructure from an audit tool is a conversation I do not want to
have, and a dump of the tool list is a one-line request.
"""
from __future__ import annotations

import json
from pathlib import Path

from ahaudit.definitions import (DefinitionSet, DefinitionSource,
                                  ToolDefinition)


class IntrospectionError(ValueError):
    pass


def from_tools_list(payload: dict, *, server: str = "unknown",
                    source: str = "third-party") -> DefinitionSet:
    """Parse a tools/list response.

    Accepts either the result envelope or the bare object, because what
    gets handed to me is about evenly split between the two.
    """
    tools = payload.get("tools")
    if tools is None and isinstance(payload.get("result"), dict):
        tools = payload["result"].get("tools")
    if not isinstance(tools, list):
        raise IntrospectionError(
            "expected a 'tools' array, at the top level or under "
            "'result'")

    defs = []
    for t in tools:
        if "name" not in t:
            raise IntrospectionError("a tool entry has no 'name'")
        schema = (t.get("inputSchema") or t.get("input_schema")
                  or t.get("parameters") or {})
        defs.append(ToolDefinition(
            name=t["name"],
            description=t.get("description", "") or "",
            parameters=schema.get("properties", schema) or {},
            server=server,
            source=DefinitionSource(source),
        ))
    return DefinitionSet(definitions=defs)


def load(path: str | Path, *, server: str = "unknown",
         source: str = "third-party") -> DefinitionSet:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, list):
        raw = {"tools": raw}
    return from_tools_list(raw, server=server, source=source)


def merge(declared: DefinitionSet | None,
          observed: DefinitionSet) -> tuple[DefinitionSet, list[str]]:
    """Return the observed set plus a list of differences.

    The differences are the interesting output: a manifest that says
    one thing and a server that serves another is a finding regardless
    of which one is worse.
    """
    notes: list[str] = []
    if declared is None:
        return observed, ["no declared definitions to compare against"]

    declared_by_name = {d.name: d for d in declared.definitions}
    observed_by_name = {d.name: d for d in observed.definitions}

    for name in sorted(set(observed_by_name) - set(declared_by_name)):
        notes.append(f"{name}: present on the server, not declared")
    for name in sorted(set(declared_by_name) - set(observed_by_name)):
        notes.append(f"{name}: declared, not present on the server")
    for name in sorted(set(declared_by_name) & set(observed_by_name)):
        if declared_by_name[name].digest() != \
                observed_by_name[name].digest():
            notes.append(f"{name}: definition text differs from the "
                         f"declared one")

    observed.pinned_digest = declared.pinned_digest
    observed.reread_on_reconnect = declared.reread_on_reconnect
    observed.reread_on_notification = declared.reread_on_notification
    observed.namespaced_by_server = declared.namespaced_by_server
    observed.approval_scope = declared.approval_scope
    observed.shows_description_at_approval = \
        declared.shows_description_at_approval
    return observed, notes
