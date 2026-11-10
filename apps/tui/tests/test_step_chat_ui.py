"""The chat inside a step: "Type something." and "Chat about this" at Scope, Plan, Approval.

The step's menu hides while you chat and comes back on Esc. A line asking to change the
scope opens a tick list (you tick; the AI never changes it); anything else is answered by
the Core API's AI (the fake API in tests).
"""

import pytest
from textual.widgets import SelectionList

from reconix import store
from reconix.core_api import client as api_client
from reconix.widgets import (
    ChatBar,
    ChoiceMenu,
    FlowProgress,
    PlanPanel,
    Question,
    ScopePanel,
    StepChat,
    TickList,
    UserMessage,
)

from .support import (
    wait_for_run,
    NETWORK,
    SIZE,
    ask_in_chat,
    chat_about_this,
    chat_menu,
    chat_menu_ready,
    chat_text,
    run_ui_to,
    screen_text,
    settle,
    step_menu,
    type_in_menu,
    type_request,
    wait_until,
)


@pytest.fixture
def model_active(reachable):
    """A configured, tested and active model, approved for the Core API (/provider's OK)."""
    store.set_provider("openai", api_key="sk-1234", models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    store.core_api_approve()


def fake_model(monkeypatch, reply=None) -> list:
    """The Core API's chat (the fake API) answers "model answer N", or `reply`; returns what
    each chat call got, as [{"role": "user", "content": <line sent>}]."""
    fake = api_client._send.__self__
    original = fake.answer
    calls: list = []

    def answer(method, path, body, full):
        if method == "POST" and path.endswith("/chat"):
            calls.append([{"role": "user", "content": body["content"]}])
            text = reply if reply is not None else f"model answer {len(calls)}"
            return {"reply": {"content_masked": text}}
        return original(method, path, body, full)

    monkeypatch.setattr(fake, "answer", answer)
    return calls


async def ui_to_approval(app, pilot, risk: str = "MEDIUM") -> str:
    """Start the demo and pass gates until the first approval gate of `risk` (the fake API
    holds its MEDIUM, then its HIGH step); returns that gate."""
    from .support import pass_gate, run_ui_to, wait_for_run

    await run_ui_to(app, pilot, "plan")
    while True:
        await pass_gate(app, pilot)
        await wait_for_run(pilot)
        gate = store.waiting_gate()
        assert gate, "the run ended before that approval"
        if gate.startswith("approval:") and store.get_approval(gate[9:]).risk == risk:
            return gate


def _question_shown(app) -> bool:
    return any(q.display for q in app.screen.query(Question) if not q.has_class("chat-decision"))


def _chat_choices(app) -> list:
    """The labels of the menu inside the chat."""
    menu = chat_menu(app)
    return [choice.label for choice in menu._choices] if menu else []


def _step_line(app) -> str:
    return str(app.screen.query_one(FlowProgress).render())


async def test_type_something_opens_the_chat_and_hides_the_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        type_in_menu(app, "looks fine")
        await wait_until(pilot, lambda: "looks fine" in chat_text(app), what="the chat")
        assert store.list_feedback()[-1].text == "looks fine"
        assert "◆ reconix" in chat_text(app)  # the built-in reply, at once
        assert "thinking" not in chat_text(app)
        assert not _question_shown(app)
        assert store.waiting_gate() == "scope"  # still waits for you


async def test_the_model_answers_and_you_stay_in_chat(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        type_in_menu(app, "why these ports?")
        await wait_until(pilot, lambda: "model answer 1" in chat_text(app), what="answer 1")
        assert calls[-1][-1]["content"].startswith("About ")
        await ask_in_chat(app, pilot, "and the tools?")
        await wait_until(pilot, lambda: "model answer 2" in chat_text(app), what="answer 2")
        assert app.screen.query_one(StepChat).input.has_focus
        assert not store.is_scope_approved()


async def test_chat_about_this_shows_the_scope_card_and_esc_brings_the_menu_back(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        chat_about_this(app)
        await wait_until(pilot, lambda: bool(app.screen.query(ScopePanel)), what="the card")
        await settle(pilot)
        chat = app.screen.query_one(StepChat)
        assert chat.query(ScopePanel)  # the card, as on the screen
        text = chat_text(app)
        assert NETWORK in text and "nmap" in text
        assert chat_menu(app) is None  # you came to talk, not decide
        assert chat.input.has_focus
        assert not _question_shown(app)
        await pilot.press("escape")
        await settle(pilot)
        assert not app.screen.query(StepChat)
        assert _question_shown(app)
        assert step_menu(app).has_focus
        assert store.waiting_gate() == "scope"


async def test_chat_about_this_at_the_plan_prints_the_plan(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        chat_about_this(app)
        await wait_until(pilot, lambda: bool(app.screen.query(PlanPanel)), what="the card")
        text = screen_text(app.screen.query_one(PlanPanel))
        assert "Find open ports" in text and "nmap" in text  # the API plan's steps
        assert not app.screen.query_one("#plan-list").display


async def test_chat_about_this_at_an_approval_prints_the_action(app):
    async with app.run_test(size=SIZE) as pilot:
        await ui_to_approval(app, pilot)
        chat_about_this(app)
        await wait_until(pilot, lambda: "Approval ·" in chat_text(app), what="the approval")
        assert "risk" in chat_text(app)
        assert store.list_approval_decisions() == []


async def test_asking_to_add_a_port_opens_your_tick_list(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 7070")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        assert "model answer 1" in chat_text(app)  # the model answers it first
        assert len(calls) == 1
        rows = app.screen.query_one(SelectionList)
        ticked = {f"port:{p}" for p in before} | {f"tool:{t}" for t in store.get_scope().tools}
        assert set(rows.selected) == ticked  # only what the scope allows today
        assert "port:7070" not in rows.selected  # nothing new ticked for you
        rows.select("port:7070")  # you tick it
        rows.focus()
        await pilot.press("enter")
        await settle(pilot)
        assert 7070 in store.get_scope().allowed_ports
        assert not app.screen.query(TickList)
        assert "7070" in chat_text(app)
        assert app.screen.query(StepChat)  # you stay in chat


async def test_esc_on_the_tick_list_changes_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 7070")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        assert "Only you can change the scope" in chat_text(app)  # the built-in reply
        app.screen.query_one(SelectionList).select("port:7070")
        await pilot.press("escape")
        await settle(pilot)
        assert store.get_scope().allowed_ports == before
        assert app.screen.query(StepChat)
        assert "No change to the scope" in chat_text(app)


async def test_a_scope_change_from_the_plan_step_reopens_the_scope(app, model_active, monkeypatch):
    fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        assert store.is_scope_approved()
        type_in_menu(app, "add port 7070")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        rows = app.screen.query_one(SelectionList)
        assert "port:7070" not in rows.selected  # the AI's suggestion is unticked
        rows.select("port:7070")  # you tick it
        rows.focus()
        await pilot.press("enter")
        await wait_until(pilot, lambda: not store.is_scope_approved(), what="the scope re-opened")
        # the scope re-opened to a draft with your port, back on the Scope step to approve
        assert store.get_scope().status == "DRAFT"
        assert 7070 in store.get_scope().allowed_ports
        assert store.waiting_gate() == "scope"


async def test_typed_markup_shows_literally(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        type_in_menu(app, "is [bold]this[/bold] ok?")
        await wait_until(pilot, lambda: "[bold]this[/bold]" in chat_text(app), what="echo")


async def test_the_question_box_is_pinned_at_the_bottom(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        type_in_menu(app, "hello")
        await wait_until(pilot, lambda: bool(app.screen.query(ChatBar)), what="the bar")
        await settle(pilot)
        bar = app.screen.query_one(ChatBar)
        body = app.screen.query_one("#body")
        assert bar.region.bottom == body.region.bottom  # docked under the chat
        assert bar.query_one("#step-chat-input").has_focus
        await pilot.press("escape")
        await settle(pilot)
        assert not app.screen.query(ChatBar)


async def test_a_model_claiming_it_changed_the_scope_is_corrected(app, model_active, monkeypatch):
    """A model may say "added"; Reconix's own line follows it and the scope is unchanged."""
    from reconix.llm import guardrail
    from reconix.store import scope_ask

    fake_model(monkeypatch, "Port 7070 has been added.")
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 7070")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        text = chat_text(app)
        assert text.index("has been added") < text.index("Only you can change the scope")
        assert store.list_chat()[-1].text == scope_ask.ONLY_YOU  # in the model's history
        assert store.get_scope().allowed_ports == before
    assert "Never say you changed" in guardrail.SYSTEM_PROMPT


# --- a decision typed in the chat: the step's own menu, never the model ---------------------
async def test_a_typed_decision_shows_the_menu_and_no_model_is_asked(
    app, model_active, monkeypatch
):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "apporve that scope")  # a typo still counts
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert calls == []  # the model never saw it
        text = chat_text(app)
        assert "nothing is approved" in text and "Only you decide this" in text
        assert _chat_choices(app) == [
            "Approve scope",
            "Edit manifest",
            "Reject",
            "Chat about this",
        ]  # typing anywhere goes to the chat
        assert "1. Approve scope" not in chat_text(app)  # no numbers: a digit types
        assert "type to chat" in chat_text(app)
        assert not app.screen.query_one(ChatBar).display  # the menu, not the input
        assert not store.is_scope_approved()
        # The focus is queued until the menu has drawn: wait for it, don't race it.
        await wait_until(pilot, lambda: chat_menu(app).has_focus, what="the menu focused")
        await pilot.press("enter")  # 1. Approve scope
        await wait_until(pilot, lambda: store.waiting_gate() == "plan", what="the plan gate")
        await settle(pilot)
        assert store.is_scope_approved()
        assert not app.screen.query(StepChat)  # the chat closed
        line = _step_line(app)
        assert "✓ Template" in line and "! Plan" in line  # the step line moved


async def test_typing_on_the_chat_menu_brings_the_input_back_and_is_answered(
    app, model_active, monkeypatch
):
    """A second line typed while the menu shows goes to the input (like "Chat about this")
    and is asked; its Enter never picks the highlighted "Approve scope"."""
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "yes")  # line 1: the menu shows
        menu = await chat_menu_ready(app, pilot)
        assert menu.highlighted_id == "approve"
        for key in "what is this":  # line 2, typed on the menu
            await pilot.press("space" if key == " " else key)
        chat = app.screen.query_one(StepChat)
        assert chat.input.value == "what is this" and chat.input.has_focus
        assert chat_menu(app) is None  # the menu went
        assert app.screen.query_one(ChatBar).display  # the input is back
        await pilot.press("enter")
        await wait_until(
            pilot, lambda: "model answer 1" in chat_text(app), what="the reply to line 2"
        )
        assert len(calls) == 1 and "what is this" in calls[0][-1]["content"]
        assert not store.is_scope_approved()  # typing decided nothing
        assert store.waiting_gate() == "scope"
        assert app.screen.query(StepChat) and chat_menu(app) is None
        assert app.screen.query_one(ChatBar).display
        assert "what is this" not in [f.text for f in store.list_feedback()]  # a chat line


async def test_a_digit_on_the_chat_menu_types_and_never_approves(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "yes")
        await chat_menu_ready(app, pilot)
        await pilot.press("1")  # outside the chat: 1 = Approve
        await settle(pilot)
        chat = app.screen.query_one(StepChat)
        assert chat.input.value == "1" and chat.input.has_focus
        assert chat_menu(app) is None
        assert not store.is_scope_approved()
        assert store.waiting_gate() == "scope"


async def test_chat_about_this_in_the_chat_menu_brings_the_input_back(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "yes")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        app.screen.post_message(ChoiceMenu.Chosen(chat_menu(app), "chat"))
        await settle(pilot)
        assert chat_menu(app) is None
        assert app.screen.query_one(ChatBar).display
        assert app.screen.query_one(StepChat).input.has_focus
        assert not store.is_scope_approved()
        assert store.waiting_gate() == "scope"


async def test_a_saved_tick_list_shows_the_new_scope_card_and_the_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "add port 7070")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        rows = app.screen.query_one(SelectionList)
        rows.select("port:7070")
        rows.focus()
        await pilot.press("enter")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        chat = app.screen.query_one(StepChat)
        [card] = chat.query(ScopePanel)
        assert "7070" in screen_text(card) and "draft" in str(card.border_subtitle)
        assert "Scope updated" in chat_text(app)
        assert not store.is_scope_approved()


async def test_show_the_scope_prints_the_card(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "show the scope")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert app.screen.query_one(StepChat).query(ScopePanel)


async def test_yes_at_the_plan_shows_the_plan_menu_and_run_plan_runs(
    app, model_active, monkeypatch
):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        await wait_until(pilot, lambda: not store.plan_drafting(), what="the plan draft")
        type_in_menu(app, "yes")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert calls == []
        assert _chat_choices(app)[0] == "Run plan" and "nothing has run" in chat_text(app)
        assert not store.is_plan_started()
        app.screen.post_message(ChoiceMenu.Chosen(chat_menu(app), "run"))
        await wait_until(pilot, store.is_plan_started, what="the plan to run")
        await wait_for_run(pilot)  # let the switch to Execution and the plan's send settle


async def test_a_question_about_the_decision_is_answered_then_the_menu(
    app, model_active, monkeypatch
):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "should I approve it?")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert len(calls) == 1 and "model answer 1" in chat_text(app)
        assert not store.is_scope_approved()


async def test_approve_in_chat_keeps_the_high_double_check(app):
    from reconix.screens.approval import ApprovalScreen
    from reconix.screens.choice import ChoiceScreen

    async with app.run_test(size=SIZE) as pilot:
        gate = await ui_to_approval(app, pilot, "HIGH")
        await wait_until(pilot, lambda: isinstance(app.screen, ApprovalScreen), what="approval")
        type_in_menu(app, "approve")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        app.screen.post_message(ChoiceMenu.Chosen(chat_menu(app), "approve"))
        await wait_until(
            pilot, lambda: isinstance(app.screen, ChoiceScreen), what="the double check"
        )
        assert store.decision_for(gate[9:]) is None  # nothing approved yet


async def test_a_new_menu_replaces_the_one_shown_before(app):
    """Saving the ticks shows a menu; typing a decision right after shows a new one (it
    crashed with a duplicate id while the first was still leaving)."""
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "add more scope")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        rows = app.screen.query_one(SelectionList)
        rows.focus()
        await pilot.press("enter")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the first menu")
        await ask_in_chat(app, pilot, "apporve that scope")
        await ask_in_chat(app, pilot, "yes")
        await settle(pilot)
        assert len(app.screen.query(".chat-decision")) == 1
        await wait_until(pilot, lambda: chat_menu(app).has_focus, what="the menu focused")
        await pilot.press("enter")
        await wait_until(pilot, store.is_scope_approved, what="the approval")


async def test_the_plan_shows_your_request_not_the_chat_line(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "apporve that scope")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        await pilot.press("enter")
        await wait_until(pilot, lambda: store.waiting_gate() == "plan", what="the plan gate")
        app.goto("plan")
        await settle(pilot)
        [shown] = app.screen.query(UserMessage)
        assert NETWORK in str(shown.content) and "apporve" not in str(shown.content)


# --- the model's ports, the plan card and the plan's order ----------------------------------
async def test_ports_the_model_names_are_offered_unticked(app, model_active, monkeypatch):
    reply = (
        "To scan 12 ports, add port 4000 along with 7071 (HTTP-ALT), 7072 (APP) and 7073 (ADMIN)."
    )
    fake_model(monkeypatch, reply)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "i need to add more port to 4000 also and i need 12 port to scan")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        rows = app.screen.query_one(SelectionList)
        values = [rows.get_option_at_index(i).value for i in range(rows.option_count)]
        for port in (4000, 7071, 7072, 7073):
            assert f"port:{port}" in values and f"port:{port}" not in rows.selected
        assert "port:12" not in values  # a count, not a port
        prompt = rows.get_option_at_index(values.index("port:7071")).prompt
        assert "suggested by the model" in str(prompt)
        assert store.get_scope().allowed_ports == before  # nothing changed by itself


async def test_give_the_plan_shows_the_plan_card_and_the_menu(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        chat_about_this(app)
        await wait_until(pilot, lambda: bool(app.screen.query(StepChat)), what="the chat")
        await ask_in_chat(app, pilot, "give the plan")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert calls == []  # the card, not the model's list
        assert len(app.screen.query_one(StepChat).query(PlanPanel)) == 2
        assert _chat_choices(app)[0] == "Run plan"


# --- a second change in the same chat: a fresh list, never a duplicate id -------------------
def _mounted(app, kind) -> list:
    return [w for w in app.screen.query(kind) if w.is_mounted]


async def test_a_second_scope_change_shows_a_fresh_tick_list(app):
    """RULE-04: a second scope change mounts a new tick list while the old one is still
    leaving; it must not clash with it."""
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 7070")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        await ask_in_chat(app, pilot, "add 7070, 0, 99999, 8080 and then scan 12 ports")
        await wait_until(pilot, lambda: len(_mounted(app, TickList)) == 1, what="one list")
        await settle(pilot)
        (ticks,) = _mounted(app, TickList)
        rows = ticks.query_one(SelectionList)
        assert rows.has_focus  # Space/Enter work at once
        values = [rows.get_option_at_index(i).value for i in range(rows.option_count)]
        assert "port:7070" in values and "port:0" not in values and "port:99999" not in values
        assert "port:12" not in values  # a count, not a port
        assert chat_text(app).count("Only you can change the scope") == 2
        assert store.get_scope().allowed_ports == before  # nothing changed by typing
        await pilot.press("enter")  # the new list saves
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert not _mounted(app, TickList)


async def test_a_plan_change_from_the_plan_step_redrafts_the_plan(app, model_active, monkeypatch):
    fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        author_before = store.plan_author()
        type_in_menu(app, "add a login brute-force step")
        # the AI answers, then Reconix re-drafts the plan and shows the new plan card
        await wait_until(
            pilot,
            lambda: (
                "re-drafted plan" in chat_text(app).lower()
                or "re-drafting" in chat_text(app).lower()
            ),
            what="the re-draft note",
        )
        await wait_until(
            pilot,
            lambda: bool(app.screen.query_one(StepChat).query(PlanPanel)),
            what="the new plan card",
        )
        assert store.is_scope_approved()  # the scope did not change
        assert not store.is_plan_started()  # nothing ran
        assert store.plan_author() == author_before  # still an AI draft


async def test_the_ai_suggests_tools_at_the_scope_step(app, model_active, fake_api, monkeypatch):
    from reconix.app import ReconixApp
    from reconix.widgets.manifest import manifest_text

    monkeypatch.setattr(ReconixApp, "SUGGEST_SCOPE_ON_REVIEW", True)
    # katana and ffuf are default web tools; arjun (hidden parameters) is not, so it is
    # the one that gets suggested.
    fake_api.reply = (
        "To list the site's paths, crawl it with katana and discover hidden parameters with arjun."
    )
    async with app.run_test(size=SIZE) as pilot:
        await type_request(pilot, "i want to list all paths on http://shop.example.com")
        # the AI reads the goal, then the card and a tick list of its suggestions appear.
        await wait_until(
            pilot,
            lambda: bool(app.screen.query("#scope-suggest-ticks")),
            what="the suggestion tick list under the card",
        )
        suggested = store.suggested_tools()
        assert "arjun" in suggested  # named by the model, not default
        assert "Katana" not in suggested  # already in the scope (crawl)
        assert "arjun" not in store.get_scope().tools  # scope unchanged until you tick
        notes = dict(store.suggested_tool_notes())
        assert notes["arjun"]  # each suggestion states its purpose
        # the card stays visible (its "Your goal" line); the suggestions are the tick list,
        # not a read-only list on the card (so they are never shown twice).
        assert app.screen.query_one(ScopePanel)
        card = manifest_text(store.get_scope(), with_suggestions=False).plain
        assert "Your goal" in card and "Suggested for your goal" not in card
        rows = app.screen.query_one("#scope-suggest-ticks").query_one(SelectionList)
        values = {opt.value for opt in rows.options}
        assert "tool:arjun" in values and "tool:Katana" not in values
        assert not rows.selected  # unticked
        # ticking a suggestion adds it to the scope (a union; the template tools stay)
        rows.select("tool:arjun")
        rows.focus()
        await pilot.press("enter")
        await settle(pilot)
        assert "arjun" in store.get_scope().tools
        assert "Nuclei" in store.get_scope().tools  # template default kept


async def test_the_scope_card_waits_for_the_goal_read(app, model_active, fake_api, monkeypatch):
    """No glitch: while the AI reads the goal, the screen shows a 'reading…' spinner and no
    card; the card and the suggestion list appear together, once, when the read lands."""
    import threading

    from reconix.app import ReconixApp

    monkeypatch.setattr(ReconixApp, "SUGGEST_SCOPE_ON_REVIEW", True)
    release = threading.Event()

    def slow_read(_request):
        release.wait(5)
        return "To list the paths, crawl with katana and find parameters with arjun."

    monkeypatch.setattr(store, "fetch_scope_suggest", slow_read)
    async with app.run_test(size=SIZE) as pilot:
        await type_request(pilot, "list all paths on http://shop.example.com")
        # while the read is in flight: the reading spinner, no card, no tick list yet
        await wait_until(
            pilot, lambda: bool(app.screen.query("#template-activity")), what="the reading spinner"
        )
        assert app.screen._reading()
        assert not app.screen.query(ScopePanel)
        assert not app.screen.query("#scope-suggest-ticks")
        release.set()
        # the read lands: the card and its suggestion list show together, spinner gone
        await wait_until(pilot, lambda: bool(app.screen.query(ScopePanel)), what="the card")
        assert app.screen.query("#scope-suggest-ticks")
        assert not app.screen.query("#template-activity")
