"""Every gate through the screens, on the run the Core API gives (the fake API in tests):
run the plan, a MEDIUM and a HIGH approval (HIGH: a double check, then the typed target),
reject, stop, and pausing (nothing runs until you decide)."""

import pytest
from rich.text import Text
from textual.widgets import Input, Static

from reconix import store
from reconix.screens import ApprovalScreen, ChoiceScreen, ExecutionScreen, PlanScreen
from reconix.screens.forms.typed_target import TypedTargetForm
from reconix.widgets import RunLog

from .support import (
    SIZE,
    choose_by_keys,
    event_kinds,
    pass_gate,
    run_ui_to,
    settle,
    wait_for_run,
    wait_until,
)


def screen_text(app) -> str:
    return " ".join(str(w.render()) for w in app.screen.query(Static))


def gate_risk() -> str:
    gate = store.waiting_gate()
    if not gate.startswith("approval:"):
        return ""
    return store.get_approval(gate.split(":", 1)[1]).risk


async def run_to_risk(app, pilot, risk: str) -> str:
    """Pass every gate until the run waits for an approval of `risk`; returns its id."""
    await run_ui_to(app, pilot, "plan")
    while gate_risk() != risk:
        assert store.waiting_gate(), "the run ended before that approval"
        await pass_gate(app, pilot)
        await wait_for_run(pilot)
    return store.waiting_gate().split(":", 1)[1]


async def test_run_plan_sends_it_and_the_low_step_runs(app, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan")
        assert isinstance(app.screen, PlanScreen)
        assert fake_api.tool_runs() == []  # nothing before Run plan
        await pilot.press("1")  # Run plan
        await wait_for_run(pilot)
        assert store.is_plan_started()
        assert fake_api.tool_runs() == ["NMAP"]  # LOW ran at once
        assert store.phase_progress()["discovery"] > 0
        assert gate_risk() == "MEDIUM"
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)  # MEDIUM waits for you


async def test_medium_approval_runs_the_one_step(app, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "MEDIUM")
        assert isinstance(app.screen, ApprovalScreen)
        assert app.focused.highlighted_id == "details"  # a stray Enter is harmless
        await pilot.press("1")  # Approve & run
        await wait_for_run(pilot)
        assert store.is_approved(request_id)
        assert "NUCLEI" in fake_api.tool_runs()
        assert gate_risk() == "HIGH"
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)


async def test_high_asks_for_a_double_check(app):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "HIGH")
        assert not app.screen.query(Input)  # nothing to type yet
        assert app.focused.highlighted_id == "details"  # a stray Enter is harmless
        await pilot.press("1")  # Approve & run
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)  # the double check
        assert "approval.confirmation_requested" in event_kinds()
        assert not store.is_approved(request_id)


async def test_high_confirmation_defaults_to_no_and_voids_the_token(app):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "HIGH")
        await pilot.press("1")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("2")  # digits do nothing here
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("enter")  # "No, go back"
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert not store.is_approved(request_id)
        assert "approval.confirmation_declined" in event_kinds()


async def test_high_yes_asks_for_the_target_typed_in(app, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "HIGH")
        await pilot.press("1")
        await settle(pilot)
        await pilot.press("down", "enter")  # Yes
        await settle(pilot)
        form = app.screen
        assert isinstance(form, TypedTargetForm)
        assert form.query_one("#target", Input).value == ""  # never filled in for you
        await pilot.press("escape")  # back: nothing approved
        await settle(pilot)
        assert not store.is_approved(request_id)
        assert "SQLMAP" not in fake_api.tool_runs()


async def test_high_with_the_typed_target_completes_the_run(app, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "HIGH")
        target = store.get_approval(request_id).target
        await pass_gate(app, pilot)  # Yes + the typed target
        await wait_for_run(pilot)
        assert store.is_completed()
        assert "SQLMAP" in fake_api.tool_runs()
        assert store.decision_for(request_id).typed_target == target
        await settle(pilot)
        assert isinstance(app.screen, ExecutionScreen)
        assert "assessment complete" in str(app.screen.query_one("#exec-hint", Static).render())


async def test_a_wrong_typed_target_is_refused_and_asked_again(app, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "HIGH")
        await pilot.press("1")
        await settle(pilot)
        await pilot.press("down", "enter")  # Yes
        await settle(pilot)
        app.screen.query_one("#target", Input).value = "https://other.example.com/"
        app.screen.query_one("#submit").press()
        await wait_for_run(pilot)
        assert store.waiting_gate() == f"approval:{request_id}"  # the API refused it
        assert not store.is_approved(request_id)
        assert "SQLMAP" not in fake_api.tool_runs()


async def test_a_digit_never_rejects_an_approval(app):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "MEDIUM")
        await pilot.press("2")  # Reject has no number
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert store.decision_for(request_id) is None


async def test_reject_skips_the_step_and_the_plan_goes_on(app, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "MEDIUM")
        await choose_by_keys(pilot, "reject")
        await wait_until(pilot, lambda: gate_risk() == "HIGH", what="the next approval")
        assert store.decision_for(request_id).decision == "REJECTED"
        assert fake_api.approvals[request_id]["approval_status"] == "REJECTED"
        assert "NUCLEI" not in fake_api.tool_runs()
        assert not store.get_run().stopped


async def test_esc_on_an_approval_decides_later(app):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "MEDIUM")
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, ExecutionScreen)
        assert store.waiting_gate() == f"approval:{request_id}"
        assert store.decision_for(request_id) is None
        await pilot.press("enter")  # back to the decision
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)


async def test_ctrl_c_asks_then_stops(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_to_risk(app, pilot, "MEDIUM")
        await pilot.press("escape")
        await settle(pilot)
        await pilot.press("ctrl+c")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("enter")  # "Keep running" is first
        await settle(pilot)
        assert not store.is_finished()
        await pilot.press("ctrl+c")
        await settle(pilot)
        await pilot.press("down", "enter")  # Stop now
        await settle(pilot)
        assert store.get_run().stopped == "you stopped it"


async def test_execution_shows_the_apis_steps_and_tool_output(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        app.goto("execution")
        await settle(pilot)
        text = "\n".join(app.screen.query_one(RunLog).plain_lines())
        assert "Step 1: Find open ports" in text
        assert "nmap on https://staging.example.com/: completed" in text
        assert "Assessment completed" in text
        assert "fake-session-token" not in text


async def test_approval_without_a_waiting_action_lists_the_decisions(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        app.goto("approval")
        await settle(pilot)
        text = screen_text(app)
        assert "no action is waiting" in text
        assert text.count("✓ approved") == 2


async def test_scope_text_with_markup_is_shown_literally(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        # edit_scope refuses unknown tools; set them directly to check the display still escapes
        store.lists.current().scope.tools = ["[/oops] ZAP", "[bold]x"]
        await pass_gate(app, pilot)  # approve
        await wait_for_run(pilot)
        await pass_gate(app, pilot)  # run the plan
        await wait_for_run(pilot)
        await pilot.press("escape")  # leave the approval for later
        await settle(pilot)
        assert isinstance(app.screen, ExecutionScreen)
        subtitle = app.screen.query_one(RunLog).border_subtitle  # stored escaped
        assert "[/oops] ZAP, [bold]x" in Text.from_markup(subtitle).plain


async def test_an_api_approval_has_nothing_to_edit(app):
    async with app.run_test(size=SIZE) as pilot:
        request_id = await run_to_risk(app, pilot, "MEDIUM")
        assert not store.can_edit(request_id)                    # the API's step, as checked
        with pytest.raises(store.StoreValidationError):
            store.edit_approval(request_id, "https://other.example.com/")
