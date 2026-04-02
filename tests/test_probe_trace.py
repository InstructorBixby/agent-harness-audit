from ahaudit.findings import Severity
from ahaudit.probe import load_builtins, run_all

load_builtins()

COMPLETE = {"events": [
    {"proposed": "send_email", "provenance": ["doc:1"],
     "authz": "allow", "arguments": {"to": "a@b.c"},
     "result": "queued", "agent": "root"},
]}

THIN = [{"proposed": "send_email", "result": "queued"}]


def test_no_trace_artefact_is_no_findings(good):
    assert run_all(good, {}) == []


def test_complete_trace_matches_a_complete_declaration(good):
    assert run_all(good, {"trace": COMPLETE}) == []


def test_declared_but_absent_is_high(good):
    findings = run_all(good, {"trace": THIN})
    assert findings
    assert all(f.confidence == "observed" for f in findings)
    assert any(f.severity is Severity.HIGH and "arguments" in f.claim
               for f in findings)


def test_observed_but_undeclared_is_info(good):
    for f in ("records_context_provenance", "records_authz_decision",
              "records_executed_arguments", "records_agent_identity"):
        setattr(good.trace, f, False)
    findings = run_all(good, {"trace": COMPLETE})
    assert findings and all(f.severity is Severity.INFO
                            for f in findings)


def test_unparseable_artefact(good):
    findings = run_all(good, {"trace": {"nope": 1}})
    assert findings[0].title.endswith("no recognisable events")


def test_a_bare_list_is_accepted(good):
    assert run_all(good, {"trace": THIN})


def test_alternative_key_names_are_recognised(good):
    alt = [{"intent": "x", "sources": [], "decision": "allow",
            "args": {}, "output": "", "actor": "root"}]
    assert run_all(good, {"trace": alt}) == []
