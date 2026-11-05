"""The AI reads the operator's goal at the Scope step and suggests tools (store/scope_suggest).

The fake API answers the one chat ask; the suggestions are offered unticked and only the
operator's tick changes the scope.
"""


from reconix import store

from .support import play_until_gate


def _to_scope_with_goal(goal: str) -> None:
    store.start_run(goal, "web_url")
    assert play_until_gate() == "scope"


def _suggest(fake_api, reply: str):
    fake_api.reply = reply
    req = store.scope_suggest_request()
    assert req is not None
    raw = store.fetch_scope_suggest(req)
    return store.apply_scope_suggest(req, raw)


def test_a_request_needs_a_goal_and_a_draft_scope(fake_api):
    _to_scope_with_goal("list all paths on http://shop.example.com")
    assert store.scope_suggest_request() is not None


def test_the_ai_suggests_catalog_tools_for_the_goal(fake_api):
    _to_scope_with_goal("i want to list all paths on http://shop.example.com")
    used = _suggest(fake_api, "To enumerate the site's paths, crawl it with katana and "
                              "brute-force directories with ffuf and gobuster.")
    assert used
    assert store.suggested_tools() == ["ffuf", "gobuster", "Katana"]
    # they are offered unticked, and the scope is unchanged until you tick
    choices = store.scope_tick_choices()
    assert set(choices.suggested_tools) == {"ffuf", "gobuster", "Katana"}
    ticked = {name for name, on in choices.tools if on}
    assert "Katana" not in ticked
    assert "Katana" not in store.get_scope().tools


def test_only_catalog_tools_in_the_list_are_picked_up(fake_api):
    _to_scope_with_goal("scan http://shop.example.com")
    _suggest(fake_api, "I would run nikto and nmap and metasploit here.")
    # nmap and metasploit are not in the web template's suggest list; nikto is (and is not
    # already in the scope, unlike Nuclei)
    assert store.suggested_tools() == ["Nikto"]


def test_ticking_a_suggested_tool_adds_it_to_the_scope(fake_api):
    _to_scope_with_goal("list paths on http://shop.example.com")
    _suggest(fake_api, "Use katana to crawl.")
    before = list(store.get_scope().tools)
    store.edit_scope(tools=[*before, "Katana"])
    assert "Katana" in store.get_scope().tools


def test_the_evaluation_runs_once(fake_api):
    _to_scope_with_goal("list paths on http://shop.example.com")
    _suggest(fake_api, "Use katana.")
    assert store.scope_suggest_request() is None     # already evaluated
    assert not store.scope_suggesting()


def test_a_failed_ask_leaves_the_template_scope(fake_api):
    _to_scope_with_goal("list paths on http://shop.example.com")
    req = store.scope_suggest_request()
    store.scope_suggest_failed(req, "the model is down")
    assert not store.scope_suggesting()
    assert store.get_assessment().scope_suggest is None


def test_the_catalog_matches_the_kali_tool_specs():
    """The TUI's Kali catalog stays in sync with services/ai tool_specs (the source)."""
    import json
    from pathlib import Path

    from reconix.store.kali_catalog import KALI_TOOLS

    specs = Path(__file__).resolve().parents[3] / \
        "services/ai/src/reconix_ai/tool_specs/tool_specs.json"
    if not specs.exists():
        import pytest
        pytest.skip("tool_specs.json not in this checkout")
    names = {t["name"] for t in json.loads(specs.read_text())["tools"]}
    assert set(KALI_TOOLS) == names


def test_no_destructive_tool_is_ever_suggested():
    from reconix.store.kali_catalog import KALI_TOOLS, suggestible

    for cats in (["web", "zap"], ["network", "recon"], ["source"], ["web", "api", "zap"]):
        for tool in suggestible(cats):
            assert not tool.destructive
            assert not KALI_TOOLS[tool.name].destructive
