from ahaudit.checks import REGISTRY
from ahaudit.checks.arguments import _wide_params
from ahaudit.definitions import DefinitionSet, ToolDefinition


def run(h):
    return REGISTRY["AHA-014"](h)


def test_enum_and_integer_are_narrow():
    assert _wide_params({"kind": {"type": "string",
                                  "enum": ["a", "b"]},
                         "count": {"type": "integer"}}) == []


def test_free_string_is_wide():
    assert _wide_params({"url": {"type": "string"}}) == ["url"]


def test_untyped_is_wide():
    assert _wide_params({"anything": {}}) == ["anything"]


def test_no_definitions(good):
    good.definitions = None
    assert run(good) == []


def test_reachless_tool_is_ignored(good):
    good.definitions = DefinitionSet([ToolDefinition(
        name="lookup_record", parameters={"q": {"type": "string"}})])
    assert run(good) == []


def test_reachy_tool_with_a_free_string(good):
    good.definitions = DefinitionSet([ToolDefinition(
        name="get_weather", parameters={"city": {"type": "string"}})])
    findings = run(good)
    assert findings[0].evidence["tools"][0]["tool"] == "get_weather"


def test_definition_for_an_undeclared_tool_is_skipped(good):
    good.definitions = DefinitionSet([ToolDefinition(
        name="ghost", parameters={"x": {"type": "string"}})])
    assert run(good) == []
