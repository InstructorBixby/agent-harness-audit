from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity
from ahaudit.model import Capability, Reach, Tool


def run(harness):
    return REGISTRY["AHA-002"](harness)


def test_good_harness_is_clean(good):
    # The research context reads the web and holds no tools; the answer
    # context holds a tool and reads only system and principal text.
    assert run(good) == []


def test_untrusted_plus_capability(good):
    good.contexts[1].tools = ["get_weather"]
    findings = run(good)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "research" in findings[0].evidence["context"]


def test_private_data_plus_egress_is_critical(good):
    good.tools.append(Tool(
        name="post_webhook",
        capabilities=[Capability("post", Reach.EXTERNAL_NETWORK,
                                 egress=True)],
        runs_as="requesting-principal"))
    good.contexts[0].sources.append(good.contexts[1].sources[1])
    good.contexts[0].tools.append("post_webhook")
    findings = run(good)
    assert findings[0].severity is Severity.CRITICAL
    assert "three properties" in findings[0].claim


def test_reported_per_context_not_per_harness(good):
    good.contexts[1].tools = ["get_weather"]
    good.contexts[0].sources.append(good.contexts[1].sources[1])
    good.contexts[0].tools.append("get_weather")
    assert {f.evidence["context"] for f in run(good)} == \
        {"answer", "research"}


def test_untrusted_with_no_reachy_tool_is_not_a_finding(good):
    good.contexts[1].tools = ["lookup_record"]
    assert run(good) == []
