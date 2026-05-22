import warnings

from ahaudit import plugins
from ahaudit.checks import REGISTRY


class FakeEP:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


def test_installs_a_check(monkeypatch):
    def my_check(harness):
        return []

    my_check.title = "my check"
    monkeypatch.setattr(
        plugins, "entry_points",
        lambda group=None: ([FakeEP("ACME-001", lambda: my_check)]
                            if group == plugins.GROUP else []))
    assert plugins.install() == ["ACME-001"]
    assert REGISTRY["ACME-001"] is my_check
    del REGISTRY["ACME-001"]


def test_broken_plugin_warns_and_is_skipped(monkeypatch):
    def boom():
        raise RuntimeError("no")

    monkeypatch.setattr(
        plugins, "entry_points",
        lambda group=None: [FakeEP("ACME-002", boom)])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert plugins.install() == []
    assert any("ACME-002" in str(w.message) for w in caught)


def test_collision_with_a_builtin_is_refused(monkeypatch):
    from ahaudit.checks import load_builtins
    load_builtins()
    original = REGISTRY["AHA-001"]

    monkeypatch.setattr(
        plugins, "entry_points",
        lambda group=None: [FakeEP("AHA-001", lambda: (lambda h: []))])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        plugins.install()
    assert REGISTRY["AHA-001"] is original
    assert any("collides" in str(w.message) for w in caught)


def test_no_plugins_is_fine(monkeypatch):
    monkeypatch.setattr(plugins, "entry_points",
                        lambda group=None: [])
    assert plugins.install() == []
