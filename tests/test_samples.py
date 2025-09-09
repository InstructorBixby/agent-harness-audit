from pathlib import Path

import pytest

from ahaudit import manifest
from ahaudit.checks import load_builtins, run_all

SAMPLES = sorted(Path("samples").glob("*/harness.yaml"))


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.parent.name)
def test_sample_manifest_loads(path):
    assert manifest.load(path).name == path.parent.name


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.parent.name)
def test_every_sample_produces_findings(path):
    # A sample that stops producing findings means either the sample
    # was fixed by accident or a check regressed. Both are worth a red
    # build.
    load_builtins()
    assert run_all(manifest.load(path))


def test_samples_exist():
    assert len(SAMPLES) >= 2


def test_weak_02_findings_are_about_delegation():
    load_builtins()
    h = manifest.load("samples/weak-02-delegation/harness.yaml")
    checks = {f.check for f in run_all(h)}
    assert "AHA-003" in checks
    assert "AHA-001" not in checks, \
        "weak-02's authorisation path is deliberately correct"
