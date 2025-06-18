from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity


def run(harness):
    return REGISTRY["AHA-005"](harness)


def _titles(harness):
    return [f.title for f in run(harness)]


def test_good_harness_is_clean(good):
    # get_weather reaches the external network but does not egress
    # private data, and nothing writes or executes.
    assert run(good) == []


def test_model_written_dialog_is_high(good):
    good.tools[0].capabilities[0] = good.tools[0].capabilities[0].\
        __class__("post", good.tools[0].capabilities[0].reach,
                  egress=True)
    good.tools[0].requires_approval = True
    good.approval.renders_structured_call = False
    findings = run(good)
    assert any(f.severity is Severity.HIGH for f in findings)


def test_model_can_skip_is_critical(good):
    good.approval.model_can_skip = True
    assert any(f.severity is Severity.CRITICAL for f in run(good))


def test_fatigue(good):
    good.approval.prompts_per_session = 40
    assert "Approval fatigue" in _titles(good)


def test_no_approval_with_risky_tools(good):
    good.approval.enabled = False
    good.tools[0].capabilities[0] = good.tools[0].capabilities[0].\
        __class__("exec", good.tools[0].capabilities[0].reach,
                  egress=True)
    assert "No approval step for consequential tools" in _titles(good)


def test_no_approval_and_no_risky_tools_is_clean(good):
    good.approval.enabled = False
    good.tools = [good.tools[1]]
    good.contexts[0].tools = ["lookup_record"]
    good.contexts[1].tools = []
    assert run(good) == []
