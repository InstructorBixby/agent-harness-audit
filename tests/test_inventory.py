from ahaudit import inventory
from ahaudit.model import Capability, Reach, Tool


def test_rows_cover_every_tool(good):
    assert {r["tool"] for r in inventory.rows(good)} == \
        {t.name for t in good.tools}


def test_ordered_by_reach(good):
    good.tools.append(Tool(name="run_shell", capabilities=[
        Capability("sh", Reach.EXECUTE)]))
    assert inventory.rows(good)[0]["tool"] == "run_shell"


def test_untrusted_contexts_are_listed(good):
    good.contexts[1].tools = ["get_weather"]
    row = next(r for r in inventory.rows(good)
               if r["tool"] == "get_weather")
    assert row["untrusted_contexts"] == ["research"]


def test_markdown_has_a_blank_column_for_the_engineer(good):
    md = inventory.markdown(good)
    assert "narrowest version that still works" in md
    assert md.rstrip().endswith("meeting and bring them to it.")


def test_markdown_renders_every_tool(good):
    md = inventory.markdown(good)
    for t in good.tools:
        assert f"`{t.name}`" in md
