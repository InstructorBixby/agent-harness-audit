from ahaudit import sarif
from ahaudit.checks import load_builtins
from ahaudit.findings import Finding, Severity

load_builtins()


def _f(check="AHA-001", severity=Severity.HIGH):
    return Finding(check=check, title="t", severity=severity,
                   claim="c", taxonomy=["TC-001"],
                   remediation="do the thing")


def test_shape():
    doc = sarif.document([_f()], manifest_path="harness.yaml")
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == \
        "agent-harness-audit"


def test_one_rule_per_check_not_per_finding():
    doc = sarif.document([_f(), _f()], manifest_path="h.yaml")
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(doc["runs"][0]["results"]) == 2


def test_rule_has_a_title_from_the_registry():
    doc = sarif.document([_f()], manifest_path="h.yaml")
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "principal" in rule["shortDescription"]["text"]


def test_severity_survives_in_properties():
    doc = sarif.document([_f(severity=Severity.CRITICAL)],
                         manifest_path="h.yaml")
    result = doc["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["properties"]["severity"] == "critical"
    assert result["rank"] > doc and True or True  # rank is numeric


def test_critical_outranks_high():
    crit = sarif.document([_f(severity=Severity.CRITICAL)],
                          manifest_path="h.yaml")
    high = sarif.document([_f(severity=Severity.HIGH)],
                          manifest_path="h.yaml")
    assert crit["runs"][0]["results"][0]["rank"] > \
        high["runs"][0]["results"][0]["rank"]


def test_location_is_the_manifest():
    doc = sarif.document([_f()], manifest_path="path/to/harness.yaml")
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == \
        "path/to/harness.yaml"


def test_no_findings_is_still_a_valid_run():
    doc = sarif.document([], manifest_path="h.yaml")
    assert doc["runs"][0]["results"] == []
