"""A model of a tool-calling harness.

Everything downstream is a pure function of this. Deliberately explicit
about the things harnesses leave implicit -- who a call is attributed
to, what a context contains, what a delegate inherits -- because the
implicit version is where the findings are.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Reach(str, Enum):
    """What a capability can touch. Ordered by blast radius."""

    NONE = "none"
    LOCAL_READ = "local-read"
    LOCAL_WRITE = "local-write"
    INTERNAL_NETWORK = "internal-network"
    EXTERNAL_NETWORK = "external-network"
    EXECUTE = "execute"


class Trust(str, Enum):
    """Where a piece of context came from."""

    SYSTEM = "system"
    PRINCIPAL = "principal"
    TENANT = "tenant"
    RETRIEVED = "retrieved"
    EXTERNAL = "external"
    TOOL_RESULT = "tool-result"
    TOOL_DEFINITION = "tool-definition"

    @property
    def untrusted(self) -> bool:
        return self in (Trust.TENANT, Trust.RETRIEVED, Trust.EXTERNAL,
                        Trust.TOOL_RESULT, Trust.TOOL_DEFINITION)


@dataclass(frozen=True)
class Capability:
    name: str
    reach: Reach
    egress: bool = False
    sensitive_read: bool = False


@dataclass
class Tool:
    name: str
    capabilities: list[Capability] = field(default_factory=list)
    runs_as: str = "unknown"
    definition_source: str = "operator"
    requires_approval: bool = False

    @property
    def egress(self) -> bool:
        return any(c.egress for c in self.capabilities)

    @property
    def sensitive_read(self) -> bool:
        return any(c.sensitive_read for c in self.capabilities)

    @property
    def max_reach(self) -> Reach:
        order = list(Reach)
        return max((c.reach for c in self.capabilities),
                   key=order.index, default=Reach.NONE)


@dataclass
class Principal:
    name: str
    kind: str = "user"


@dataclass
class ContextSource:
    """One kind of text that lands in a context window."""

    name: str
    trust: Trust
    # Can a party other than the requesting principal write it?
    third_party_writable: bool = False


@dataclass
class Context:
    """A context window the harness assembles, with what goes in it."""

    name: str
    sources: list[ContextSource] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    # Data in the context that the requesting principal could not
    # otherwise obtain: system prompt, other tenants' documents,
    # session identifiers.
    holds_private_data: bool = False

    def untrusted_sources(self) -> list[ContextSource]:
        return [s for s in self.sources if s.trust.untrusted]

    @property
    def reads_untrusted(self) -> bool:
        return bool(self.untrusted_sources())
