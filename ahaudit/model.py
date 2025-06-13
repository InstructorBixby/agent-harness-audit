"""A model of a tool-calling harness.

Everything downstream is a pure function of this. Deliberately explicit
about the things harnesses leave implicit -- who a call is attributed
to, what a context contains, what a delegate inherits -- because the
implicit version is where the findings are.

The dataclasses are slotted. A typo'd field name silently added an
attribute and the check then read the real field as still-false, which
is the failure mode where a tool reports a finding that is not there.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Reach(str, Enum):
    NONE = "none"
    LOCAL_READ = "local-read"
    LOCAL_WRITE = "local-write"
    INTERNAL_NETWORK = "internal-network"
    EXTERNAL_NETWORK = "external-network"
    EXECUTE = "execute"


class Trust(str, Enum):
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


class AuthzSubject(str, Enum):
    REQUESTING_PRINCIPAL = "requesting-principal"
    SESSION = "session"
    SERVICE_IDENTITY = "service-identity"
    MODEL_SUPPLIED = "model-supplied"
    NONE = "none"


class AuthzTiming(str, Enum):
    PER_CALL = "per-call"
    PER_SESSION = "per-session"
    AT_STARTUP = "at-startup"
    NEVER = "never"


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    reach: Reach
    egress: bool = False
    sensitive_read: bool = False


@dataclass(slots=True)
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


@dataclass(slots=True)
class Principal:
    name: str
    kind: str = "user"


@dataclass(slots=True)
class ContextSource:
    name: str
    trust: Trust
    third_party_writable: bool = False


@dataclass(slots=True)
class Context:
    name: str
    sources: list[ContextSource] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    holds_private_data: bool = False

    def untrusted_sources(self) -> list[ContextSource]:
        return [s for s in self.sources if s.trust.untrusted]

    @property
    def reads_untrusted(self) -> bool:
        return bool(self.untrusted_sources())


@dataclass(slots=True)
class Authorisation:
    subject: AuthzSubject = AuthzSubject.NONE
    timing: AuthzTiming = AuthzTiming.NEVER
    halts_on_denial: bool = False
    enforced_by: str = "unknown"


@dataclass(slots=True)
class Delegation:
    enabled: bool = False
    inherits_tools: bool = True
    inherits_credentials: bool = True
    inherits_context: bool = True
    inherits_approvals: bool = True
    attenuates: bool = False
    shares_budget: bool = False


@dataclass(slots=True)
class Trace:
    records_proposed_action: bool = False
    records_context_provenance: bool = False
    records_authz_decision: bool = False
    records_executed_arguments: bool = False
    records_result: bool = False
    records_agent_identity: bool = False

    @property
    def missing(self) -> list[str]:
        return [f for f in self.__slots__
                if getattr(self, f) is False]

    @property
    def reconstructable(self) -> bool:
        return not self.missing


@dataclass(slots=True)
class Approval:
    enabled: bool = False
    renders_structured_call: bool = False
    model_can_skip: bool = False
    prompts_per_session: int = 0


@dataclass(slots=True)
class Budget:
    steps: int | None = None
    tool_calls: int | None = None
    tokens: int | None = None
    shared_across_delegates: bool = False


@dataclass(slots=True)
class Harness:
    name: str
    tools: list[Tool] = field(default_factory=list)
    contexts: list[Context] = field(default_factory=list)
    principals: list[Principal] = field(default_factory=list)
    authorisation: Authorisation = field(default_factory=Authorisation)
    delegation: Delegation = field(default_factory=Delegation)
    trace: Trace = field(default_factory=Trace)
    approval: Approval = field(default_factory=Approval)
    budget: Budget = field(default_factory=Budget)
    notes: str = ""

    def tool(self, name: str) -> Tool | None:
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def tools_in(self, context: Context) -> list[Tool]:
        out = []
        for name in context.tools:
            t = self.tool(name)
            if t is not None:
                out.append(t)
        return out
