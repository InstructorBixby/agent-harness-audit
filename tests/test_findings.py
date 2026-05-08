from ahaudit.findings import Finding, Severity, sort_findings


def _f(check="AHA-002", title="t", severity=Severity.HIGH, **ev):
    return Finding(check=check, title=title, severity=severity,
                   claim="c", evidence=ev)


def test_worst_first():
    out = sort_findings([_f(severity=Severity.LOW),
                         _f(severity=Severity.CRITICAL)])
    assert out[0].severity is Severity.CRITICAL


def test_same_severity_sorted_by_check():
    out = sort_findings([_f(check="AHA-009"), _f(check="AHA-001")])
    assert [f.check for f in out] == ["AHA-001", "AHA-009"]


def test_same_check_and_severity_is_stable():
    a = _f(context="research")
    b = _f(context="answer")
    assert sort_findings([a, b]) == sort_findings([b, a])


def test_tie_broken_by_evidence_not_by_insertion():
    a = _f(context="research")
    b = _f(context="answer")
    assert sort_findings([a, b])[0].evidence["context"] == "answer"


def test_to_dict_serialises_severity():
    assert _f().to_dict()["severity"] == "high"
