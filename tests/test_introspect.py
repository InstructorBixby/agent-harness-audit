import json

import pytest

from ahaudit import introspect
from ahaudit.definitions import DefinitionSet, ToolDefinition

TOOLS_LIST = {
    "result": {
        "tools": [
            {"name": "lookup_record",
             "description": "Look up a customer record.",
             "inputSchema": {"type": "object", "properties": {
                 "id": {"type": "string", "description": "Record id."}}}},
            {"name": "send_email",
             "description": "Send mail on the user's behalf.",
             "inputSchema": {"type": "object", "properties": {
                 "to": {"type": "string"}, "body": {"type": "string"}}}},
        ]
    }
}


def test_parses_the_result_envelope():
    ds = introspect.from_tools_list(TOOLS_LIST, server="vendor")
    assert [d.name for d in ds.definitions] == ["lookup_record",
                                                "send_email"]
    assert ds.definitions[0].server == "vendor"


def test_parses_a_bare_tools_object():
    ds = introspect.from_tools_list({"tools": TOOLS_LIST["result"]["tools"]})
    assert len(ds.definitions) == 2


def test_parameter_descriptions_are_kept():
    ds = introspect.from_tools_list(TOOLS_LIST)
    assert ds.definitions[0].parameters["id"]["description"] == \
        "Record id."


def test_missing_tools_array():
    with pytest.raises(introspect.IntrospectionError):
        introspect.from_tools_list({"nope": []})


def test_tool_without_a_name():
    with pytest.raises(introspect.IntrospectionError):
        introspect.from_tools_list({"tools": [{"description": "x"}]})


def test_load_from_file(tmp_path):
    p = tmp_path / "tools.json"
    p.write_text(json.dumps(TOOLS_LIST))
    assert len(introspect.load(p).definitions) == 2


def test_merge_reports_additions_and_removals():
    declared = DefinitionSet([
        ToolDefinition(name="lookup_record",
                       description="Look up a customer record.",
                       parameters={"id": {"type": "string",
                                          "description": "Record id."}}),
        ToolDefinition(name="gone"),
    ])
    observed = introspect.from_tools_list(TOOLS_LIST)
    merged, notes = introspect.merge(declared, observed)
    joined = " | ".join(notes)
    assert "send_email: present on the server, not declared" in joined
    assert "gone: declared, not present on the server" in joined
    assert merged is observed


def test_merge_reports_changed_text():
    declared = DefinitionSet([ToolDefinition(
        name="lookup_record", description="Look it up.")])
    observed = introspect.from_tools_list(TOOLS_LIST)
    _, notes = introspect.merge(declared, observed)
    assert any("text differs" in n for n in notes)


def test_merge_carries_the_declared_policy_fields():
    declared = DefinitionSet([], approval_scope="definition",
                             namespaced_by_server=True)
    observed = introspect.from_tools_list(TOOLS_LIST)
    merged, _ = introspect.merge(declared, observed)
    assert merged.approval_scope == "definition"
    assert merged.namespaced_by_server is True
