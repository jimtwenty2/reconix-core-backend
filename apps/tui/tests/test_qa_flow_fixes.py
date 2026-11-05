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
    pass_gate,
    chat_text,
    run_ui_to,
    settle,
    step_menu,
    type_in_menu,
    wait_for_run,
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


async def test_view_details_from_the_chat_menu_then_esc_focuses_the_approval_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan")
        await pass_gate(app, pilot)                  # Run plan: the API's first steps play
        await wait_for_run(pilot)
        assert store.waiting_gate().startswith("approval:")
        await settle(pilot)
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


async def test_a_host_change_in_the_chat_shows_no_tick_list(app, model_active):
    store.core_api_approve()  # your OK in /provider: the API may use the remote model
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "add 10.0.0.99 to the scope")
        await wait_until(pilot, lambda: "Hosts can't change" in chat_text(app), what="reply")
        await settle(pilot)
        assert not app.screen.query(TickList)


# --- F4: a question at Start is answered, never turned into a template hint ---------------
def test_a_question_with_a_keyword_goes_to_the_ai_not_the_template():
    assert store.submit_prompt("what is my api key?") == "ask"
    assert store.submit_prompt("how does the api template work") == "ask"
    assert not store.get_run().started
    assert store.submit_prompt("test my API please") == "answered"      # a request: the hint
    assert "API needs" in store.list_chat()[-1].text


def test_without_a_local_model_a_question_still_goes_to_the_core_api():
    # No /provider model: the Core API answers with its own model; no template hint.
    assert store.submit_prompt("what is my api key?") == "ask"
    assert all("API needs" not in entry.text for entry in store.list_chat())
    assert not store.get_run().started


def test_with_a_real_model_a_question_before_a_target_asks_the_model(model_active):
    # reconix-ai: a question at Start goes to the real model (static keeps it local)
    assert store.submit_prompt("what is my api key?") == "ask"
    assert all("API needs" not in entry.text for entry in store.list_chat())


def test_a_question_with_a_target_still_starts_the_run():
    assert store.submit_prompt("test the api at https://api.example.com") == "started"
    assert store.get_run().started


# --- F5: a check moved to another host can't confirm the finding --------------------------
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
    app, model_active, fake_api
):
    store.core_api_approve()  # your OK in /provider: the API may use the remote model
    fake_api.reply = "model answer 1"
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


def test_the_saved_copy_keeps_its_shape(model_active):
    from reconix.store.snapshot import snapshot

    store.core_api_approve()
    store.submit_prompt("scan 10.0.0.0/24")
    store.llm_answer("what is in scope?")
    entry = store.list_chat()[-1]
    assert entry.speaker == "reconix" and entry.text == "The API's answer."
    saved = snapshot(store.get_assessment())
    rows = [row for row in saved["timeline"] if row["type"] == "chat"]
    assert rows[-1]["who"] == "reconix" and "author" not in rows[-1]


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
