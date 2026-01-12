import pytest
import yaml

from ahaudit import policy
from ahaudit.findings import Finding, Severity


def _f(check="AHA-001", severity=Severity.HIGH):
    return Finding(check=check, title="t", severity=severity,
                   claim="c")


def test_no_policy_changes_nothing():
    p = policy.Policy()
    findings = [_f()]
    assert p.apply(findings) == findings


def test_lowering_a_severity_is_recorded():
    p = policy.Policy(severities={"AHA-001": Severity.LOW})
    out = p.apply([_f()])[0]
    assert out.severity is Severity.LOW
    assert out.evidence["severity_overridden"] == {
        "from": "high", "to": "low"}


def test_disabled_check_is_dropped_and_noted():
    p = policy.Policy(disabled={"AHA-001": "tool reaches one address"})
    assert p.apply([_f()]) == []
    assert p.notes() == [
        "AHA-001 disabled: tool reaches one address"]


def test_original_finding_is_not_mutated():
    original = _f()
    policy.Policy(severities={"AHA-001": Severity.LOW}).apply([original])
    assert original.severity is Severity.HIGH


def test_load(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump({
        "severities": {"AHA-007": "info"},
        "disabled": {"AHA-011": "single-tenant, single-user"}}))
    loaded = policy.load(p)
    assert loaded.severities["AHA-007"] is Severity.INFO
    assert loaded.disabled["AHA-011"]


def test_disabling_without_a_reason_is_an_error(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump({"disabled": {"AHA-011": ""}}))
    with pytest.raises(policy.PolicyError) as e:
        policy.load(p)
    assert "needs a reason" in str(e.value)


def test_unknown_policy_key(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump({"severites": {}}))
    with pytest.raises(policy.PolicyError):
        policy.load(p)


def test_bad_severity_value(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump({"severities": {"AHA-001": "spicy"}}))
    with pytest.raises(policy.PolicyError):
        policy.load(p)
