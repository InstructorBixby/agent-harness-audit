import json

import pytest

from ahaudit import serialise
from ahaudit.checks import load_builtins, run_all

jsonschema = pytest.importorskip("jsonschema")


def test_schema_is_valid_json():
    assert serialise.schema()["$defs"]["finding"]["required"]


def test_document_validates(good):
    load_builtins()
    findings = run_all(good)
    doc = serialise.document(good, findings)
    jsonschema.validate(doc, serialise.schema())


def test_weak_document_validates(good):
    # The interesting direction: a harness with findings in it.
    load_builtins()
    good.authorisation.subject = good.authorisation.subject.__class__(
        "service-identity")
    good.trace.records_executed_arguments = False
    doc = serialise.document(good, run_all(good))
    assert doc["findings"]
    jsonschema.validate(doc, serialise.schema())


def test_severity_serialises_as_a_string(good):
    load_builtins()
    good.trace.records_result = False
    doc = json.loads(serialise.dumps(good, run_all(good)))
    assert doc["findings"][0]["severity"] in (
        "info", "low", "medium", "high", "critical")


def test_findings_are_sorted_worst_first(good):
    load_builtins()
    good.authorisation.subject = good.authorisation.subject.__class__(
        "none")
    good.trace.records_result = False
    doc = serialise.document(good, run_all(good))
    ranks = ["critical", "high", "medium", "low", "info"]
    got = [ranks.index(f["severity"]) for f in doc["findings"]]
    assert got == sorted(got)


def test_schema_version_is_present(good):
    load_builtins()
    assert serialise.document(good, [])["schema_version"] == "1"
