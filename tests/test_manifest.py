import pytest
import yaml

from ahaudit import manifest
from ahaudit.model import AuthzSubject, Reach, Trust

MINIMAL = {
    "harness": {
        "name": "example",
        "tools": [{"name": "fetch",
                   "capabilities": [{"name": "http",
                                     "reach": "external-network",
                                     "egress": True}],
                   "runs_as": "service"}],
        "contexts": [{"name": "main",
                      "sources": [{"name": "web",
                                   "trust": "external",
                                   "third_party_writable": True}],
                      "tools": ["fetch"],
                      "holds_private_data": True}],
        "authorisation": {"subject": "service-identity",
                          "timing": "per-session"},
    }
}


def test_from_dict_roundtrip():
    h = manifest.from_dict(MINIMAL)
    assert h.name == "example"
    assert h.tools[0].egress is True
    assert h.tools[0].max_reach is Reach.EXTERNAL_NETWORK
    assert h.contexts[0].sources[0].trust is Trust.EXTERNAL
    assert h.authorisation.subject is AuthzSubject.SERVICE_IDENTITY


def test_load_from_file(tmp_path):
    p = tmp_path / "h.yaml"
    p.write_text(yaml.safe_dump(MINIMAL))
    assert manifest.load(p).name == "example"


def test_missing_harness_key():
    with pytest.raises(manifest.ManifestError) as e:
        manifest.from_dict({"nope": {}})
    assert "harness" in str(e.value)


def test_bad_enum_lists_the_options():
    bad = {"harness": {"name": "x", "authorisation":
                       {"subject": "vibes"}}}
    with pytest.raises(manifest.ManifestError) as e:
        manifest.from_dict(bad)
    assert "requesting-principal" in str(e.value)


def test_capability_without_reach():
    bad = {"harness": {"name": "x", "tools": [
        {"name": "t", "capabilities": [{"name": "c"}]}]}}
    with pytest.raises(manifest.ManifestError) as e:
        manifest.from_dict(bad)
    assert "reach" in str(e.value)


def test_context_referencing_an_undeclared_tool():
    bad = {"harness": {"name": "x", "contexts": [
        {"name": "main", "tools": ["ghost"]}]}}
    with pytest.raises(manifest.ManifestError) as e:
        manifest.from_dict(bad)
    assert "ghost" in str(e.value)


def test_defaults_are_pessimistic():
    # An unspecified authority model is the dangerous one, so the
    # defaults have to describe the dangerous case rather than a
    # convenient one.
    h = manifest.from_dict({"harness": {"name": "x"}})
    assert h.authorisation.subject is AuthzSubject.NONE
    assert h.trace.reconstructable is False
    assert h.budget.steps is None
