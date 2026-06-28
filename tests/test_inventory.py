from ahaudit import inventory
from ahaudit.model import Capability, Reach, Tool


def test_rows_cover_every_tool(good):
    assert {r["tool"] for r in inventory.rows(good)} == \
        {t.name for t in good.tools}


def test_ordered_by_reach(good):
    good.tools.append(Tool(name="run_shell", capabilities=[
        Capability("sh", Reach.EXECUTE)]))
    assert inventory.rows(good)[0]["tool"] == "run_shell"


def test_egress_beats_no_egress_at_equal_reach(good):
    good.tools = [
        Tool(name="quiet", capabilities=[
            Capability("a", Reach.EXTERNAL_NETWORK)]),
        Tool(name="loud", capabilities=[
            Capability("b", Reach.EXTERNAL_NETWORK, egress=True)]),
    ]
    good.contexts[0].tools = []
    good.contexts[1].tools = []
    assert [r["tool"] for r in inventory.rows(good)] == \
        ["loud", "quiet"]


def test_exposure_breaks_the_next_tie(good):
    good.tools = [
        Tool(name="a", capabilities=[Capability("x", Reach.LOCAL_READ)]),
        Tool(name="b", capabilities=[Capability("x", Reach.LOCAL_READ)]),
    ]
    good.contexts[0].tools = ["a"]
    good.contexts[1].tools = ["b"]
    # Only the research context reads untrusted content.
    assert [r["tool"] for r in inventory.rows(good)] == ["b", "a"]


def test_order_is_independent_of_declaration_order(good):
    first = [r["tool"] for r in inventory.rows(good)]
    good.tools.reverse()
    assert [r["tool"] for r in inventory.rows(good)] == first


def test_untrusted_contexts_are_listed(good):
    good.contexts[1].tools = ["get_weather"]
    row = next(r for r in inventory.rows(good)
               if r["tool"] == "get_weather")
    assert row["untrusted_contexts"] == ["research"]


def test_markdown_has_a_blank_column_for_the_engineer(good):
    md = inventory.markdown(good)
    assert "narrowest version that still works" in md
