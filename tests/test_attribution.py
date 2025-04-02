from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity
from ahaudit.model import AuthzSubject, AuthzTiming


def run(harness):
    return REGISTRY["AHA-001"](harness)


def test_good_harness_is_clean(good):
    assert run(good) == []


def test_no_authorisation_is_critical(good):
    good.authorisation.subject = AuthzSubject.NONE
    findings = run(good)
    assert [f.severity for f in findings] == [Severity.CRITICAL]
    assert "TC-001" in findings[0].taxonomy


def test_no_authorisation_short_circuits(good):
    # Reporting "no check at all" and "the check is per session" as two
    # findings is noise; the first makes the second meaningless.
    good.authorisation.subject = AuthzSubject.NONE
    good.authorisation.timing = AuthzTiming.PER_SESSION
    assert len(run(good)) == 1


def test_service_identity(good):
    good.authorisation.subject = AuthzSubject.SERVICE_IDENTITY
    findings = run(good)
    assert findings[0].severity is Severity.HIGH
    assert findings[0].taxonomy == ["TC-009"]


def test_model_supplied_subject_is_critical(good):
    good.authorisation.subject = AuthzSubject.MODEL_SUPPLIED
    assert any(f.severity is Severity.CRITICAL for f in run(good))


def test_per_session_timing(good):
    good.authorisation.timing = AuthzTiming.PER_SESSION
    findings = run(good)
    assert len(findings) == 1
    assert "per-session" in findings[0].claim
