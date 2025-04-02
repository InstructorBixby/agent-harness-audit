import pytest

from ahaudit.checks import load_builtins
from ahaudit.model import (Approval, Authorisation, AuthzSubject,
                           AuthzTiming, Budget, Capability, Context,
                           ContextSource, Delegation, Harness,
                           Principal, Reach, Tool, Trace, Trust)

load_builtins()


@pytest.fixture
def good() -> Harness:
    """A harness that should produce no findings.

    Worth having first. A tool that cannot describe a safe system has
    no way to tell a finding from its own default assumptions.
    """
    return Harness(
        name="good",
        principals=[Principal("alice"), Principal("bob")],
        tools=[
            Tool(name="get_weather",
                 capabilities=[Capability("weather", Reach.EXTERNAL_NETWORK)],
                 runs_as="requesting-principal"),
            Tool(name="lookup_record",
                 capabilities=[Capability("read", Reach.LOCAL_READ,
                                          sensitive_read=True)],
                 runs_as="requesting-principal"),
        ],
        contexts=[
            Context(name="answer",
                    sources=[ContextSource("system", Trust.SYSTEM),
                             ContextSource("user", Trust.PRINCIPAL)],
                    tools=["lookup_record"],
                    holds_private_data=True),
            Context(name="research",
                    sources=[ContextSource("system", Trust.SYSTEM),
                             ContextSource("web", Trust.EXTERNAL,
                                           third_party_writable=True)],
                    tools=[],
                    holds_private_data=False),
        ],
        authorisation=Authorisation(
            subject=AuthzSubject.REQUESTING_PRINCIPAL,
            timing=AuthzTiming.PER_CALL,
            halts_on_denial=True,
            enforced_by="data layer, row-level security"),
        delegation=Delegation(enabled=True, inherits_tools=False,
                              inherits_credentials=False,
                              inherits_context=False,
                              inherits_approvals=False,
                              attenuates=True, shares_budget=True),
        trace=Trace(records_proposed_action=True,
                    records_context_provenance=True,
                    records_authz_decision=True,
                    records_executed_arguments=True,
                    records_result=True,
                    records_agent_identity=True),
        approval=Approval(enabled=True, renders_structured_call=True,
                          model_can_skip=False, prompts_per_session=2),
        budget=Budget(steps=40, tool_calls=60, tokens=400_000,
                      shared_across_delegates=True),
    )
