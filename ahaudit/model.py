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

    SYSTEM = "system"          # the operator wrote it
    PRINCIPAL = "principal"    # the requesting user wrote it
    TENANT = "tenant"          # another user in the same tenant
    RETRIEVED = "retrieved"    # a corpus the operator controls
    EXTERNAL = "external"      # the open web, mail, a third party
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
    # True if invoking it can move bytes to a party the requesting
    # principal does not control. The egress leg.
    egress: bool = False
    # True if it can read data the requesting principal could not
    # otherwise obtain.
    sensitive_read: bool = False


@dataclass
class Tool:
    name: str
    capabilities: list[Capability] = field(default_factory=list)
    # Which identity the implementation authenticates as.
    runs_as: str = "unknown"
    # Where the definition text came from.
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
    kind: str = "user"          # user | service | operator
