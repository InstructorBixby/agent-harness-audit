from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity
from ahaudit.model import (Capability, ContextSource, Reach, Tool,
                           Trust)


def run(h):
    return REGISTRY["AHA-015"](h)


def test_good_harness_is_clean(good):
    assert run(good) == []


def test_writer_plus_readback_source(good):
    good.tools.append(Tool(name="write_file", capabilities=[
        Capability("fs", Reach.LOCAL_WRITE)]))
    good.contexts[0].tools.append("write_file")
    good.contexts[0].sources.append(ContextSource(
        "rules-file", Trust.RETRIEVED, third_party_writable=True))
    findings = run(good)
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence["writers"] == ["write_file"]


def test_readback_without_a_writer_is_clean(good):
    good.contexts[0].sources.append(ContextSource(
        "rules-file", Trust.RETRIEVED, third_party_writable=True))
    assert run(good) == []


def test_shared_memory_store(good):
    good.concurrency.memory_store = True
    titles = [f.title for f in run(good)]
    assert "Persistent memory shared between runs" in titles


def test_both_at_once(good):
    good.concurrency.memory_store = True
    good.tools.append(Tool(name="write_file", capabilities=[
        Capability("fs", Reach.LOCAL_WRITE)]))
    good.contexts[0].tools.append("write_file")
    good.contexts[0].sources.append(ContextSource(
        "rules-file", Trust.RETRIEVED, third_party_writable=True))
    assert len(run(good)) == 2
