from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity


def run(harness):
    return REGISTRY["AHA-008"](harness)


def _titles(h):
    return [f.title for f in run(h)]


def test_good_harness_is_clean(good):
    assert run(good) == []


def test_missing_limits(good):
    good.budget.steps = None
    good.budget.tokens = None
    findings = run(good)
    assert findings[0].title == "Loop is not bounded"
    assert "steps" in findings[0].claim and "tokens" in findings[0].claim


def test_unshared_budget_with_delegation(good):
    good.budget.shared_across_delegates = False
    assert "Budgets not shared across delegates" in _titles(good)


def test_unshared_budget_without_delegation_is_fine(good):
    good.delegation.enabled = False
    good.budget.shared_across_delegates = False
    assert "Budgets not shared across delegates" not in _titles(good)


def test_non_terminal_denial_is_high(good):
    good.authorisation.halts_on_denial = False
    findings = [f for f in run(good) if "denial" in f.title]
    assert findings[0].severity is Severity.HIGH
