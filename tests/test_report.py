from ahaudit import report
from ahaudit.findings import Finding, Severity


def _f(**kw):
    base = dict(check="AHA-001", title="t", severity=Severity.HIGH,
                claim="c")
    base.update(kw)
    return Finding(**base)


def test_clean_report_says_what_clean_means(good):
    md = report.markdown(good, [])
    assert "the declaration is sound" in md


def test_finding_with_no_evidence_renders(good):
    md = report.markdown(good, [_f(evidence={})])
    assert "### evidence" not in md
    assert "AHA-001" in md


def test_inventory_is_included(good):
    assert "blast-radius inventory" in report.markdown(good, [])


def test_inventory_can_be_omitted(good):
    assert "blast-radius inventory" not in report.markdown(
        good, [], with_inventory=False)


def test_taxonomy_appendix_only_when_there_are_findings(good):
    assert "taxonomy cross-reference" not in report.markdown(good, [])
    md = report.markdown(good, [_f(taxonomy=["TC-001"])])
    assert "| AHA-001 | TC-001 |" in md


def test_text_summary_is_worst_first(good):
    out = report.text_summary(good, [
        _f(severity=Severity.LOW, check="AHA-004"),
        _f(severity=Severity.CRITICAL, check="AHA-002")])
    assert out.index("AHA-002") < out.index("AHA-004")
