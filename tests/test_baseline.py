from ahaudit.baseline import Baseline, fingerprint
from ahaudit.findings import Finding, Severity


def _f(check="AHA-002", context="answer", title="t"):
    return Finding(check=check, title=title, severity=Severity.HIGH,
                   claim="c", evidence={"context": context,
                                        "detail": "noise"})


def test_fingerprint_is_stable_across_rewording():
    assert fingerprint(_f(title="old wording")) == \
        fingerprint(_f(title="new wording"))


def test_fingerprint_depends_on_the_instance():
    assert fingerprint(_f(context="answer")) != \
        fingerprint(_f(context="research"))


def test_fingerprint_ignores_descriptive_evidence():
    a = _f()
    b = _f()
    b.evidence["detail"] = "different noise"
    assert fingerprint(a) == fingerprint(b)


def test_split(tmp_path):
    base = Baseline.from_findings([_f(context="answer")])
    new, known = base.split([_f(context="answer"),
                             _f(context="research")])
    assert [f.evidence["context"] for f in new] == ["research"]
    assert [f.evidence["context"] for f in known] == ["answer"]


def test_roundtrip(tmp_path):
    p = tmp_path / "baseline.json"
    Baseline.from_findings([_f()]).save(p)
    assert Baseline.load(p).is_new(_f()) is False


def test_stale_entries_are_reported():
    base = Baseline.from_findings([_f(context="gone")])
    assert base.stale([_f(context="answer")]) == ["t"]


def test_empty_baseline_makes_everything_new():
    assert Baseline().is_new(_f()) is True
