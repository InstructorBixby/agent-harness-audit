from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity


def run(h):
    return REGISTRY["AHA-011"](h)


def test_good_harness_is_clean(good):
    assert run(good) == []


def test_shared_workspace(good):
    good.concurrency.workspace = True
    findings = run(good)
    assert findings[0].severity is Severity.HIGH
    assert "AG-008" in findings[0].taxonomy


def test_shared_browser_profile_is_critical(good):
    good.concurrency.browser_profile = True
    assert run(good)[0].severity is Severity.CRITICAL


def test_unkeyed_cache_is_its_own_finding(good):
    good.concurrency.cache = True
    good.concurrency.cache_keyed_by_principal = False
    titles = [f.title for f in run(good)]
    assert "Cache not keyed by principal" in titles
    assert "Shared cache between runs" in titles


def test_keyed_cache_is_only_the_sharing_finding(good):
    good.concurrency.cache = True
    assert len(run(good)) == 1


def test_every_shared_thing_is_reported(good):
    good.concurrency.workspace = True
    good.concurrency.browser_profile = True
    good.concurrency.memory_store = True
    assert len(run(good)) == 3
