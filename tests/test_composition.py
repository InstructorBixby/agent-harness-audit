from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity
from ahaudit.model import Capability, Reach, Tool


def run(harness):
    return REGISTRY["AHA-006"](harness)


def test_good_harness_is_clean(good):
    # lookup_record reads sensitive data; nothing in its context
    # egresses.
    assert run(good) == []


def test_read_plus_egress(good):
    good.tools.append(Tool(
        name="post_webhook",
        capabilities=[Capability("post", Reach.EXTERNAL_NETWORK,
                                 egress=True)]))
    good.contexts[0].tools.append("post_webhook")
    findings = run(good)
    assert findings[0].severity is Severity.HIGH
    assert ["lookup_record", "post_webhook"] in \
        findings[0].evidence["pairs"]


def test_write_plus_execute_is_critical(good):
    good.tools += [
        Tool(name="write_file",
             capabilities=[Capability("fs", Reach.LOCAL_WRITE)]),
        Tool(name="run_shell",
             capabilities=[Capability("sh", Reach.EXECUTE)]),
    ]
    good.contexts[0].tools += ["write_file", "run_shell"]
    assert any(f.severity is Severity.CRITICAL for f in run(good))


def test_pairs_are_per_context(good):
    good.tools.append(Tool(
        name="post_webhook",
        capabilities=[Capability("post", Reach.EXTERNAL_NETWORK,
                                 egress=True)]))
    good.contexts[1].tools = ["post_webhook"]
    # Egress alone in the research context is not a pair.
    assert all(f.evidence["context"] == "answer" for f in run(good))


def test_a_single_tool_is_not_a_pair_with_itself(good):
    good.tools.append(Tool(
        name="read_and_post",
        capabilities=[Capability("rw", Reach.EXTERNAL_NETWORK,
                                 egress=True, sensitive_read=True)]))
    good.contexts[1].tools = ["read_and_post"]
    assert run(good) == []
