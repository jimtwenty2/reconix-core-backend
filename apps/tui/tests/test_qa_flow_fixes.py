"""QA flow fixes (2026-11-04): the Start prompt after a refusal, the focus after a dialog
opened from the step chat, the tick list's first row, questions at Start, and a candidate
finding confirmed only by a check on its own host."""

import pytest
from textual.widgets import SelectionList

from reconix import store
from reconix.screens import StartScreen
from reconix.widgets import ChoiceMenu, PromptBox, StepChat, TickList

from .support import (
    NETWORK,
    SIZE,
    chat_menu,
    chat_text,
    run_ui_to,
    screen_text,
    settle,
    step_menu,
    type_in_menu,
    wait_until,
)


# --- F2: a dialog opened from the menu inside the step chat gives the focus back -----------
async def _choose_in_chat(app, pilot, choice_id: str) -> None:
    await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
    app.screen.post_message(ChoiceMenu.Chosen(chat_menu(app), choice_id))
    await settle(pilot)


async def _esc_dialog(app, pilot, depth: int) -> None:
    await wait_until(pilot, lambda: len(app.screen_stack) > depth, what="the dialog")
    await pilot.press("escape")
    await wait_until(pilot, lambda: len(app.screen_stack) == depth, what="the dialog closed")
    await settle(pilot)


def _focus_is_the_step_menu(app) -> bool:
    focused = app.screen.focused
    return isinstance(focused, ChoiceMenu) and focused is step_menu(app)


async def test_edit_manifest_from_the_chat_menu_then_esc_focuses_the_step_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        depth = len(app.screen_stack)
        type_in_menu(app, "yes")
        await _choose_in_chat(app, pilot, "edit")
        await _esc_dialog(app, pilot, depth)
        assert not app.screen.query(StepChat)
        assert _focus_is_the_step_menu(app)
        assert store.waiting_gate() == "scope"
        await pilot.press("escape")  # the next Esc doesn't leave the step
        await settle(pilot)
        assert store.waiting_gate() == "scope"


async def test_edit_steps_from_the_chat_menu_then_esc_focuses_the_plan_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        depth = len(app.screen_stack)
        type_in_menu(app, "yes")
        await _choose_in_chat(app, pilot, "edit")
        await _esc_dialog(app, pilot, depth)
        assert _focus_is_the_step_menu(app)


async def test_view_details_from_the_chat_menu_then_esc_focuses_the_approval_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "approval:approval-001")
        depth = len(app.screen_stack)
        type_in_menu(app, "yes")
        await _choose_in_chat(app, pilot, "details")
        await _esc_dialog(app, pilot, depth)
        assert _focus_is_the_step_menu(app)


# --- F1: a refused line at Start stays, selected: typing replaces it ----------------------
async def _type(pilot, text: str) -> None:
    for key in text:
        await pilot.press({" ": "space", "/": "slash", ".": "full_stop"}.get(key, key))


@pytest.mark.parametrize(
    "line", ["10.0.0.300", "review repo github.com/acme", "scan 10.0.0.1-10.0.0.20"]
)
async def test_a_refused_target_is_selected_and_slash_new_replaces_it(app, line):
    async with app.run_test(size=SIZE) as pilot:
        box = app.screen.query_one(PromptBox)
        box.input.value = line
        box.input.focus()
        await pilot.press("enter")
        await settle(pilot)
        assert not store.get_run().started, line
        assert box.input.value == line                     # kept, to fix it
        assert box.input.selection == (0, len(line))      # selected: typing replaces it
        await _type(pilot, "/new")
        assert box.input.value == "/new"
        assert box.menu_open                               # the command list shows
        await pilot.press("enter")
        await settle(pilot)
        assert not store.get_run().started
        assert "new" not in (store.get_assessment().target or "")
        assert isinstance(app.screen, StartScreen)
        assert app.screen.query_one(PromptBox).input.value == ""


# --- F3: the tick list opens on the row the line named ------------------------------------
async def test_the_tick_list_opens_on_the_new_port_and_space_enter_adds_it(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        await settle(pilot)
        rows = app.screen.query_one(SelectionList)
        assert rows.has_focus
        assert rows.get_option_at_index(rows.highlighted).value == "port:3389"
        await pilot.press("space", "enter")
        await settle(pilot)
        assert store.get_scope().allowed_ports == before + [3389]   # 22 stays allowed


def test_a_suggested_port_label_fits_80_columns():
    ticks = TickList([(22, True), (3389, False)], [], suggested=[3389])
    label = ticks._port_label(3389).plain
    assert len("▐X▌ " + label) <= 80 - 16  # the chat's and the list's borders and padding
    assert "suggested by the model" in label


def test_a_tick_list_line_that_names_a_tool_opens_on_it():
    from .support import run_to

    run_to("scope", NETWORK)
    assert store.wants_scope_change("remove testssl.sh")
    assert store.answer_scope_change("remove testssl.sh").focus == "tool:testssl.sh"
    assert store.answer_scope_change("add port 080").focus == "port:80"


# --- chat (d): what the tick list can't change gets Reconix's reason instead ---------------
def test_a_port_range_a_host_and_another_tool_are_refused_with_a_reason():
    from reconix.store import scope_ask

    from .support import run_to

    run_to("scope", NETWORK)
    before = store.get_scope()
    cases = {
        "add ports 1-1024": "single ports, not a range (1-1024)",
        "add 10.0.0.99 to the scope": "Hosts can't change here",
        "add nikto": "Nikto can't be added here",
    }
    for line, words in cases.items():
        assert store.wants_scope_change(line), line
        assert store.answer_scope_change(line) is None, line   # no tick list
        assert words in store.list_chat()[-1].text, line
    assert "/new" in scope_ask.HOSTS
    after = store.get_scope()
    assert (after.allowed_ports, after.tools) == (before.allowed_ports, before.tools)


async def test_a_host_change_in_the_chat_shows_no_tick_list(app):
    store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "add 10.0.0.99 to the scope")
        await wait_until(pilot, lambda: "Hosts can't change" in chat_text(app), what="reply")
        await settle(pilot)
        assert not app.screen.query(TickList)
        assert "mock model" not in chat_text(app)


# --- F4: a question at Start is answered, never turned into a template hint ---------------
def test_a_question_with_a_keyword_goes_to_the_mock_not_the_template():
    store.use_mock()
    assert store.submit_prompt("what is my api key?") == "ask"
    assert store.submit_prompt("how does the api template work") == "ask"
    assert not store.get_run().started
    assert store.submit_prompt("test my API please") == "answered"      # a request: the hint
    assert "API needs" in store.list_chat()[-1].text


def test_without_a_model_a_question_gets_no_template_hint():
    assert store.submit_prompt("what is my api key?") == "answered"
    reply = store.list_chat()[-1].text
    assert "API needs" not in reply and "can't answer questions" in reply
    assert not store.get_run().started


def test_with_a_real_model_a_question_before_a_target_stays_local(model_active):
    assert store.submit_prompt("what is my api key?") == "answered"
    reply = store.list_chat()[-1].text
    assert "API needs" not in reply and "nothing you type is sent" in reply


def test_a_question_with_a_target_still_starts_the_run():
    assert store.submit_prompt("test the api at https://api.example.com") == "started"
    assert store.get_run().started


# --- F5: a check moved to another host can't confirm the finding --------------------------
MGMT = "Check 10.0.0.0/24 for exposed management consoles"


def _play_with_edit(value: str = "") -> None:
    from .support import decide, play_until_gate

    store.start_run(MGMT)
    while True:
        gate = play_until_gate()
        if gate is None:
            return
        if value and gate == "approval:approval-002":
            store.edit_approval("approval-002", value)
        decide(gate)


def test_the_high_check_on_the_finding_s_own_host_confirms_it():
    _play_with_edit()
    assert store.get_finding("001").validation == "CONFIRMED"


def test_a_high_check_moved_to_another_host_leaves_the_finding_unconfirmed():
    _play_with_edit("10.0.0.7:8443")
    finding = store.get_finding("001")
    assert finding.path.startswith("10.0.0.1:8443")
    assert finding.validation == "UNCONFIRMED"
    assert finding.evidence == [
        "Not collected: the check ran on 10.0.0.7:8443, not on this finding's own host and "
        "port, so it can't confirm it."
    ]


def test_a_check_moved_to_another_port_or_path_doesn_t_confirm():
    from reconix.models import ApprovalRequest, Finding
    from reconix.store.confirm_check import checks_finding

    req = ApprovalRequest.__new__(ApprovalRequest)  # only the fields the check reads
    finding = Finding.__new__(Finding)
    cases = [
        ("Host:port", "10.0.0.1:8443", "10.0.0.1:8443/manager", True),
        ("Host:port", "10.0.0.1:9443", "10.0.0.1:8443/manager", False),
        ("Path", "/api/orders/10483", "/api/orders/{id}", True),
        ("Path", "/api/users/7", "/api/orders/{id}", False),
        ("File", "app/config/settings.py", "app/config/settings.py", True),
        ("File", "app/other.py", "app/config/settings.py", False),
    ]
    for label, ran_on, where, expected in cases:
        req.param_label, req.path = label, ran_on
        finding.path = where
        assert checks_finding(req, finding) is expected, (label, ran_on)


# --- the model's lines carry the model's name; Reconix's own keep "◆ reconix" ------------
async def test_a_model_reply_in_the_step_chat_is_labelled_with_the_model(
    app, model_active, monkeypatch
):
    from .support import fake_model

    fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "why these ports?")
        await wait_until(pilot, lambda: "model answer 1" in chat_text(app), what="the answer")
        text = chat_text(app)
        assert "◆ gpt-4o-mini  model answer 1" in text
        assert "◆ reconix" not in text.split("model answer 1")[0].splitlines()[-1]
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: "Only you can change" in chat_text(app), what="line")
        assert "◆ reconix  Only you can change the scope" in chat_text(app)


async def test_the_mock_s_answer_at_start_is_labelled_with_its_name(app):
    from reconix.screens.start import _answer

    store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        box = app.screen.query_one(PromptBox)
        box.input.value = "who are you?"
        box.input.focus()
        await pilot.press("enter")
        await wait_until(pilot, lambda: len(store.last_exchange()[1]) > 0, what="the answer")
        await settle(pilot)
        label = _answer(store.last_exchange()[1]).plain
        assert label.startswith("◆ reconix-mock-1  ")


def test_the_saved_copy_keeps_its_shape():
    from reconix.store.snapshot import snapshot

    store.use_mock()
    store.submit_prompt("scan 10.0.0.0/24")
    store.llm_answer("what is in scope?")
    entry = store.list_chat()[-1]
    assert entry.author == "reconix-mock-1" and entry.speaker == "reconix"
    saved = snapshot(store.get_assessment())
    rows = [row for row in saved["timeline"] if row["type"] == "chat"]
    assert rows[-1]["who"] == "reconix" and "author" not in rows[-1]


# --- chat (b): at the target login the step chat takes what the command bar takes ---------
async def test_help_and_stop_typed_in_the_step_at_the_login_run(app):
    from reconix.screens import ExecutionScreen, HelpScreen

    from .support import toasts

    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "account")
        step = next(s for s in app.screen_stack if isinstance(s, ExecutionScreen))
        step.post_message(ChoiceMenu.Typed(ChoiceMenu(), "/help"))
        await wait_until(pilot, lambda: isinstance(app.screen, HelpScreen), what="help")
        await pilot.press("escape")
        await settle(pilot)
        depth = len(app.screen_stack)
        step.post_message(ChoiceMenu.Typed(ChoiceMenu(), "/stop"))
        await wait_until(pilot, lambda: len(app.screen_stack) > depth, what="Stop this?")
        assert "Stop" in screen_text(app.screen)              # it asks first, as the bar does
        assert not any("target login" in t for t in toasts(app))


# --- chat (c): "The scope as it stands now:" is recorded like any reply --------------------
async def test_show_the_scope_records_its_line(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "show the scope")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        you, replies = store.last_exchange()
        assert "show the scope" in you.text
        assert [e.text for e in replies] == ["The scope as it stands now:"]


# --- chat (a): a model reply loses whole escape sequences, not only ESC -------------------
def test_a_reply_s_escape_sequences_are_stripped_whole():
    from reconix.llm.guardrail import check_response

    esc = "\x1b"
    assert check_response(f"Colour {esc}[31mred{esc}[0m done") == "Colour red done"
    assert check_response(f"a {esc}]8;;http://x.example\x07link{esc}]8;;\x07 b") == "a link b"
    assert check_response("\x9b1mbold") == "bold"
    assert check_response("plain [31m text") == "plain [31m text"   # no ESC: just text


# --- chat (e): the step's wording speaks to you ------------------------------------------
def test_the_scope_review_status_says_you():
    from .support import run_to

    run_to("scope", NETWORK)
    status = store.step_status()
    assert "until you choose Run plan" in status.choices
    assert "operator" not in status.choices
