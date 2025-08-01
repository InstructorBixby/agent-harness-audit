from ahaudit.checks import REGISTRY
from ahaudit.findings import Severity
from ahaudit.model import Capability, Reach, Tool


def run(harness):
    return REGISTRY["AHA-007"](harness)


def _titles(h):
    return [f.title for f in run(h)]


def test_external_tool_without_egress_flag(good):
    # get_weather is external-network and not flagged.
    assert "External-network tools not declared as egress" in \
        _titles(good)


def test_flagged_external_tool_is_fine(good):
    good.tools[0].capabilities = [
        Capability("weather", Reach.EXTERNAL_NETWORK, egress=True)]
    assert "External-network tools not declared as egress" not in \
        _titles(good)


def test_quiet_egress_names_are_flagged(good):
    good.tools.append(Tool(
        name="emit_telemetry",
        capabilities=[Capability("stats", Reach.INTERNAL_NETWORK)]))
    findings = [f for f in run(good)
                if f.title.startswith("Quiet egress")]
    assert findings and findings[0].severity is Severity.LOW
    assert "emit_telemetry" in findings[0].evidence["tools"]


def test_no_egress_anywhere_is_info(good):
    good.tools[0].capabilities = [
        Capability("weather", Reach.LOCAL_READ)]
    findings = [f for f in run(good) if f.severity is Severity.INFO]
    assert findings and "markdown image" in findings[0].remediation


def test_inferred_findings_say_so(good):
    assert all(f.confidence == "inferred" for f in run(good))
