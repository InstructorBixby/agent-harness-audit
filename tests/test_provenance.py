from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity
from ahaudit.model import Capability, Reach, Tool


def run(h):
    return REGISTRY["AHA-012"](h)


def _expose(h):
    h.tools.append(Tool(name="write_file", capabilities=[
        Capability("fs", Reach.LOCAL_WRITE)]))
    h.contexts[1].tools = ["write_file"]
    return h


def test_no_exposed_context_is_not_a_finding(good):
    good.trace.records_context_provenance = False
    assert run(good) == []


def test_missing_provenance_in_an_exposed_context(good):
    _expose(good)
    good.trace.records_context_provenance = False
    findings = run(good)
    assert findings[0].severity is Severity.HIGH
    assert "research" in findings[0].evidence["contexts"]


def test_recorded_provenance_is_clean(good):
    _expose(good)
    assert run(good) == []


def test_unknown_enforcement_point(good):
    _expose(good)
    good.authorisation.enforced_by = "unknown"
    titles = [f.title for f in run(good)]
    assert "Authorisation enforcement point not identified" in titles
