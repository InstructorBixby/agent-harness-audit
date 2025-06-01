from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity


def run(harness):
    return REGISTRY["AHA-003"](harness)


def test_good_harness_is_clean(good):
    assert run(good) == []


def test_disabled_delegation_is_not_a_finding(good):
    good.delegation.enabled = False
    good.delegation.inherits_tools = True
    good.delegation.attenuates = False
    assert run(good) == []


def test_no_attenuation(good):
    good.delegation.inherits_tools = True
    good.delegation.attenuates = False
    titles = [f.title for f in run(good)]
    assert "Delegation does not attenuate authority" in titles


def test_inherited_approvals_is_its_own_finding(good):
    good.delegation.inherits_approvals = True
    findings = run(good)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "TC-006" in findings[0].taxonomy


def test_inherited_context_is_medium(good):
    good.delegation.inherits_context = True
    findings = run(good)
    assert findings[0].severity is Severity.MEDIUM
