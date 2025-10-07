"""Keeps the definition model attached to the harness model.

`Harness` is slotted, so the definitions field is declared there; this
module holds the manifest-facing construction so `model.py` stays free
of parsing concerns and `definitions.py` stays free of YAML.
"""
from __future__ import annotations

from ahaudit.definitions import (DefinitionSet, DefinitionSource,
                                  ToolDefinition)


def definition_set(raw: dict | None) -> DefinitionSet | None:
    if not raw:
        return None
    defs = []
    for d in raw.get("tools", []):
        defs.append(ToolDefinition(
            name=d["name"],
            description=d.get("description", ""),
            parameters=d.get("parameters", {}) or {},
            server=d.get("server", "local"),
            source=DefinitionSource(d.get("source", "third-party")),
        ))
    return DefinitionSet(
        definitions=defs,
        pinned_digest=raw.get("pinned_digest"),
        reread_on_reconnect=bool(raw.get("reread_on_reconnect", True)),
        reread_on_notification=bool(
            raw.get("reread_on_notification", True)),
        namespaced_by_server=bool(raw.get("namespaced_by_server",
                                          False)),
        approval_scope=raw.get("approval_scope", "server"),
        shows_description_at_approval=bool(
            raw.get("shows_description_at_approval", False)),
    )
