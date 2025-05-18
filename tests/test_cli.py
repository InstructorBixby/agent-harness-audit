import yaml

from ahaudit import cli

WEAK = {
    "harness": {
        "name": "weak",
        "tools": [{"name": "fetch",
                   "capabilities": [{"name": "http",
                                     "reach": "external-network",
                                     "egress": True}],
                   "runs_as": "service"}],
        "contexts": [{"name": "main",
                      "sources": [{"name": "web", "trust": "external",
                                   "third_party_writable": True}],
                      "tools": ["fetch"],
                      "holds_private_data": True}],
        "authorisation": {"subject": "service-identity",
                          "timing": "per-session"},
    }
}


def _write(tmp_path, data):
    p = tmp_path / "h.yaml"
    p.write_text(yaml.safe_dump(data))
    return str(p)


def test_list_checks(capsys):
    assert cli.main(["--list-checks"]) == 0
    assert "AHA-001" in capsys.readouterr().out


def test_no_manifest_is_usage_error(capsys):
    assert cli.main([]) == 2
    assert "manifest" in capsys.readouterr().err


def test_unknown_check_is_usage_error(capsys):
    assert cli.main([_write_dummy(), "--check", "AHA-999"]) == 2
    assert "AHA-999" in capsys.readouterr().err


def _write_dummy():
    import tempfile
    p = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    yaml.safe_dump(WEAK, p)
    p.close()
    return p.name


def test_bad_manifest_is_usage_error(tmp_path, capsys):
    p = tmp_path / "h.yaml"
    p.write_text("not: a harness")
    assert cli.main([str(p)]) == 2
    assert "harness" in capsys.readouterr().err


def test_findings_exit_nonzero(tmp_path, capsys):
    assert cli.main([_write(tmp_path, WEAK)]) == 1
    out = capsys.readouterr().out
    assert "AHA-001" in out and "AHA-002" in out


def test_markdown_written(tmp_path):
    md = tmp_path / "report.md"
    cli.main([_write(tmp_path, WEAK), "--markdown", str(md),
              "--quiet"])
    text = md.read_text()
    assert text.startswith("# Harness audit: weak")
    assert "### remediation" in text


def test_check_filter(tmp_path, capsys):
    cli.main([_write(tmp_path, WEAK), "--check", "AHA-001"])
    out = capsys.readouterr().out
    assert "AHA-001" in out and "AHA-002" not in out
