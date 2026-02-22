from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity
from ahaudit.model import Capability, ContextSource, Reach, Tool, Trust


def run(h):
    return REGISTRY["AHA-013"](h)


def _wire(h):
    h.contexts[0].sources.append(
        ContextSource("tool-results", Trust.TOOL_RESULT))
    h.tools.append(Tool(name="write_file", capabilities=[
        Capability("fs", Reach.LOCAL_WRITE)]))
    h.contexts[0].tools.append("write_file")
    return h


def test_no_tool_results_is_clean(good):
    assert run(good) == []


def test_results_plus_capability(good):
    _wire(good)
    findings = run(good)
    assert findings[0].evidence["context"] == "answer"
    assert findings[0].severity is Severity.MEDIUM


def test_worse_without_provenance(good):
    _wire(good)
    good.trace.records_context_provenance = False
    assert run(good)[0].severity is Severity.HIGH


def test_results_without_capability_is_clean(good):
    good.contexts[1].sources.append(
        ContextSource("tool-results", Trust.TOOL_RESULT))
    assert all(f.evidence["context"] != "research" for f in run(good))
