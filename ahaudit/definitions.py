"""Tool definitions as a trust relationship.

A host that loads tools from a server it did not write is having part
of its system prompt supplied by a third party: names, descriptions,
parameter names, parameter descriptions, enum values. All of it is
instruction-weighted text present in every request.

The audit questions are structural rather than textual:

- where did the definition come from, and who can change it?
- is a hash of what the operator approved pinned anywhere?
- does the host re-read definitions, and on what trigger?
- do two sources share a namespace?

This module holds the model for that, and the hashing used to answer
the second question.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum


class DefinitionSource(str, Enum):
    OPERATOR = "operator"          # vendored into the host's config
    FIRST_PARTY = "first-party"    # a service the operator runs
    THIRD_PARTY = "third-party"    # someone else's server
    REGISTRY = "registry"          # an index the operator doesn't own
    USER_INSTALLED = "user-installed"

    @property
    def operator_controlled(self) -> bool:
        return self in (DefinitionSource.OPERATOR,
                        DefinitionSource.FIRST_PARTY)


@dataclass(slots=True)
class ToolDefinition:
    """The text a server supplies for one tool."""

    name: str
    description: str = ""
    parameters: dict = field(default_factory=dict)
    server: str = "local"
    source: DefinitionSource = DefinitionSource.THIRD_PARTY

    def canonical(self) -> str:
        """Stable serialisation for hashing.

        Sorted keys throughout: two hosts listing the same tools in a
        different order must produce the same hash, or pinning is
        useless.
        """
        return json.dumps(
            {"name": self.name,
             "description": self.description,
             "parameters": self.parameters},
            sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.sha256(
            self.canonical().encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class DefinitionSet:
    """What a host loaded, and what it did about approving it."""

    definitions: list[ToolDefinition] = field(default_factory=list)
    pinned_digest: str | None = None
    reread_on_reconnect: bool = True
    reread_on_notification: bool = True
    namespaced_by_server: bool = False
    approval_scope: str = "server"   # server | tool | definition
    shows_description_at_approval: bool = False

    def digest(self) -> str:
        parts = sorted(d.digest() for d in self.definitions)
        return hashlib.sha256(
            "".join(parts).encode("utf-8")).hexdigest()[:16]

    @property
    def pinned(self) -> bool:
        return self.pinned_digest is not None

    @property
    def drifted(self) -> bool:
        return self.pinned and self.pinned_digest != self.digest()
