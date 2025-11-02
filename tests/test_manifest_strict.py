import pytest

from ahaudit import manifest
from ahaudit.definitions import DefinitionSource


def test_unknown_top_level_section():
    with pytest.raises(manifest.ManifestError) as e:
        manifest.from_dict({"harness": {"name": "x", "toolz": []}})
    assert "toolz" in str(e.value)


def test_unknown_key_lists_the_known_ones():
    with pytest.raises(manifest.ManifestError) as e:
        manifest.from_dict({"harness": {"name": "x",
                                        "trace": {"records_stuff": True}}})
    assert "records_executed_arguments" in str(e.value)


def test_misspelled_capability_key():
    with pytest.raises(manifest.ManifestError) as e:
        manifest.from_dict({"harness": {"name": "x", "tools": [
            {"name": "t", "capabilities": [
                {"name": "c", "reach": "local-read",
                 "egres": True}]}]}})
    assert "egres" in str(e.value)


def test_concurrency_section():
    h = manifest.from_dict({"harness": {"name": "x", "concurrency": {
        "workspace": True, "cache": True,
        "cache_keyed_by_principal": False}}})
    assert h.concurrency.shared == ["workspace", "cache"]


def test_definitions_section():
    h = manifest.from_dict({"harness": {"name": "x", "definitions": {
        "approval_scope": "tool",
        "tools": [{"name": "lookup", "server": "vendor",
                   "source": "registry",
                   "description": "Look it up."}]}}})
    ds = h.definitions
    assert ds.definitions[0].source is DefinitionSource.REGISTRY
    assert ds.approval_scope == "tool"
    assert ds.pinned is False


def test_definitions_absent_is_none():
    assert manifest.from_dict({"harness": {"name": "x"}}).definitions \
        is None
