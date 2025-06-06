from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity


def run(harness):
    return REGISTRY["AHA-004"](harness)


def test_complete_trace_is_clean(good):
    assert run(good) == []


def test_missing_arguments_is_high(good):
    good.trace.records_executed_arguments = False
    findings = run(good)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "EX-003" in findings[0].taxonomy


def test_missing_provenance_is_high(good):
    good.trace.records_provenance = None  # not a field; ignored
    good.trace.records_context_provenance = False
    assert run(good)[0].severity is Severity.HIGH


def test_missing_result_is_low(good):
    good.trace.records_result = False
    assert run(good)[0].severity is Severity.LOW


def test_every_gap_is_reported(good):
    for field in ("records_proposed_action",
                  "records_context_provenance",
                  "records_authz_decision",
                  "records_executed_arguments",
                  "records_result",
                  "records_agent_identity"):
        setattr(good.trace, field, False)
    assert len(run(good)) == 6
