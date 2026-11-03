"""The assessment switcher and history: reopening a run, /new, /summary and /audit.

The spec tests come first: switching resumes the run where it stands, a new assessment
starts fresh while the old ones stay listed, the summary shows the right fields, and the
audit shows the activity and the trail. Then one test per gap this branch closed — the
summary's template and status, masking in the audit, the trail scoped to one run, a late
model reply that must not land in the run now on screen, getters that return copies, and a
HIGH confirmation token that must not survive a switch.
"""

import io
import threading

import pytest
from rich.console import Console

from reconix import store
from reconix.screens import ApprovalScreen, ChoiceScreen, StartScreen
from reconix.widgets import ChoiceMenu

from .support import SIZE, decide, play_until_gate, run_to, run_to_end, screen_text, settle

SECRET = "s3cret-Pa55-from-the-chat"


# --- helpers ----------------------------------------------------------------------------------
def menu_text(screen) -> str:
    """Everything the dialog's choice menu offers, as plain text (the cards live here)."""
    menu = screen.query_one(ChoiceMenu)
    out = []
    for index in range(menu.option_count):
        console = Console(file=io.StringIO(), width=120, force_terminal=False)
        console.print(menu.get_option_at_index(index).prompt)
        out.append(console.file.getvalue())
    return "\n".join(out)


async def open_dialog(app, pilot, command: str) -> ChoiceScreen:
    app.run_command_line(command)
    await settle(pilot)
    assert isinstance(app.screen, ChoiceScreen)
    return app.screen


async def dialog_body(app, pilot, command: str) -> str:
    """The read-only body of a dialog (/summary, /audit), then close it again."""
    screen = await open_dialog(app, pilot, command)
    text = screen_text(screen)
    await pilot.press("escape")
    await settle(pilot)
    return text


def row(body: str, label: str) -> str:
    """The value of one label/value row of a details body."""
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith(label):
            return stripped[len(label):].strip()
    return ""


def current_card() -> store.AssessmentCard:
    return next(card for card in store.list_assessments() if card.current)


def high_gate() -> str:
    """Play the run to its HIGH-risk approval gate, deciding everything before it."""
    gate = play_until_gate()
    while not (gate and gate.startswith("approval:")
               and store.get_approval(gate.split(":", 1)[1]).risk == "HIGH"):
        decide(gate)
        gate = play_until_gate()
    return gate


# --- spec: switching resumes the run where it stands --------------------------------------
async def test_switching_resumes_the_run_where_it_stands(app):
    store.start_run(store.DEMO_REQUEST)
    for _ in range(4):                          # scope, plan, account, code
        decide(play_until_gate())
    store.advance()                             # past the code gate: running, between gates
    assert store.waiting_gate() == "" and not store.is_finished()
    played = [entry.message for entry in store.list_activity()]
    store.new_assessment()

    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.switch_assessment(0)
        await settle(pilot)
        assert store.waiting_gate() == "approval:approval-001"
        assert isinstance(app.screen, ApprovalScreen)
        messages = [entry.message for entry in store.list_activity()]
        assert messages[:len(played)] == played      # nothing replayed and nothing skipped
        assert len(messages) > len(played)           # it played on from where it stood


async def test_a_run_left_behind_plays_nothing_in_the_background(app):
    store.start_run(store.DEMO_REQUEST)
    for _ in range(4):
        decide(play_until_gate())
    store.advance()
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.new_assessment()
        await settle(pilot)
        left = store.list_assessments()[0]
        for _ in range(4):
            await settle(pilot)
        assert not app.controller.busy               # no step is scheduled for it
        assert store.list_assessments()[0] == left   # and it did not move


async def test_a_finished_run_opens_read_only(app):
    run_to(None)                                     # completed
    completed = store.list_assessments()[0]
    store.new_assessment()
    store.start_run("scan 10.0.0.0/24 for open ports")
    store.stop_run()                                 # stopped
    stopped = store.list_assessments()[1]
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.switch_assessment(0)
        for _ in range(4):
            await settle(pilot)
        assert store.is_completed() and not app.controller.busy
        assert store.list_assessments()[0] == completed
        app.switch_assessment(1)
        for _ in range(4):
            await settle(pilot)
        assert store.get_run().stopped and not app.controller.busy
        assert store.list_assessments()[1] == stopped


# --- spec: a new assessment starts fresh and the old ones stay listed ---------------------
async def test_new_starts_fresh_and_the_old_ones_stay_listed(app):
    run_to(None)
    first = store.get_assessment().label
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.run_command_line("/new")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert not store.get_run().started and store.list_findings() == []
        cards = store.list_assessments()
        assert [card.status for card in cards] == ["Completed", "New"]
        assert cards[0].label == first and not cards[0].current and cards[1].current

        text = menu_text(await open_dialog(app, pilot, "/assessments"))
        assert first in text and "CURRENT" in text and "New assessment" in text
        assert "Completed" in text


async def test_new_on_a_target_keeps_the_run_it_leaves_listed(app):
    run_to("scope")
    first = store.get_assessment().label
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.run_command_line("/new 10.0.0.0/24")
        await settle(pilot)
        assert store.get_assessment().target == "10.0.0.0/24"
        cards = store.list_assessments()
        assert cards[0].label == first
        assert cards[0].status == "Awaiting input" and not cards[0].current
        assert cards[1].current and cards[1].target == "10.0.0.0/24"


# --- spec: the summary shows the correct fields -------------------------------------------
async def test_the_summary_shows_the_fields_of_the_run(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        body = await dialog_body(app, pilot, "/summary")
        assert row(body, "id") == store.get_assessment().label
        assert row(body, "target") == "staging.example.com"
        assert row(body, "status") == "Completed"
        assert row(body, "template") == "Web URL"
        assert row(body, "findings") == "1 confirmed · 2 for review"
        assert row(body, "human approvals") == "3 (scope, MEDIUM, HIGH)"
        assert row(body, "blocked actions") == "1 (out of scope)"
        assert row(body, "report").startswith("not exported yet")

        path = store.generate_report("json")
        body = await dialog_body(app, pilot, "/summary")
        shown = row(body, "report").rstrip("…")     # a long path is cut to the row's width
        assert shown and path.startswith(shown)


# --- spec: the audit shows the activity and the trail -------------------------------------
async def test_the_audit_shows_the_activity_and_the_trail(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        body = await dialog_body(app, pilot, "/audit")
        assert "Activity log" in body and "Audit trail" in body
        for line in ("[USER] Scope approved", "[USER] Plan approved · testing starts",
                     "[SYS] Assessment status: Completed"):
            assert line in body
        for kind in ("request.submitted", "scope.approved", "plan.run", "approval.approved",
                     "run.completed"):
            assert kind in body
        assert body.index("scope.approved") < body.index("run.completed")


# --- gap 1 and 2: the summary's template, and the status the card shows -------------------
async def test_the_summary_template_and_status_match_the_card(app):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        body = await dialog_body(app, pilot, "/summary")       # nothing started yet
        assert (row(body, "status"), row(body, "template")) == ("New", "—")
        assert row(body, "status") == current_card().status

        run_to("scope")                                        # waiting at the scope gate
        body = await dialog_body(app, pilot, "/summary")
        assert (row(body, "status"), row(body, "template")) == ("Awaiting input", "Web URL")
        assert row(body, "status") == current_card().status

        decide("scope")
        decide(play_until_gate())                              # the plan: testing starts
        store.advance()
        body = await dialog_body(app, pilot, "/summary")
        assert row(body, "status") == current_card().status

        run_to_end()                                           # completed
        body = await dialog_body(app, pilot, "/summary")
        assert (row(body, "status"), row(body, "template")) == ("Completed", "Web URL")
        assert row(body, "status") == current_card().status


async def test_the_summary_of_a_stopped_run(app):
    run_to("scope")
    store.reject_scope()
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        body = await dialog_body(app, pilot, "/summary")
        assert (row(body, "status"), row(body, "template")) == ("Stopped", "Web URL")
        assert row(body, "status") == current_card().status


# --- gap 3: the audit masks secrets (display only) ----------------------------------------
async def test_the_audit_masks_a_secret_and_keeps_the_stored_text(app):
    run_to("scope")
    store.say_operator_line(f"the test account is password={SECRET} ok?")
    store.add_feedback("scope", f"use password={SECRET} for the login")
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        body = await dialog_body(app, pilot, "/audit")
        assert SECRET not in body
        assert "password=••••" in body
        assert "Your feedback" in body
    # masking is for the screen only: the store still holds what the operator typed
    assert any(SECRET in event.detail for event in store.list_events())
    assert any(SECRET in entry.text for entry in store.list_feedback())


async def test_the_assessments_list_masks_a_secret_in_the_cards(app):
    run_to("scope")
    store.say_operator_line(f"the test account is password={SECRET} ok?")
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        text = menu_text(await open_dialog(app, pilot, "/assessments"))
        assert SECRET not in text and store.get_assessment().target in text


# --- gap 4: the trail belongs to one run --------------------------------------------------
async def test_the_audit_shows_only_the_current_runs_trail(app):
    run_to("scope")
    store.say_operator_line("first run marker alpha-one")
    store.new_assessment()
    store.start_run("scan 10.0.0.0/24 for open ports")
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        body = await dialog_body(app, pilot, "/audit")
        assert "alpha-one" not in body and "staging.example.com" not in body
        assert "10.0.0.0/24" in body

        app.switch_assessment(0)
        await settle(pilot)
        body = await dialog_body(app, pilot, "/audit")
        assert "alpha-one" in body and "10.0.0.0/24" not in body


def test_events_and_feedback_are_tagged_with_their_assessment():
    run_to("scope")
    first = store.get_assessment().label
    store.add_feedback("scope", "keep it read-only")
    store.new_assessment()
    second = store.get_assessment().label
    store.start_run("scan 10.0.0.0/24 for open ports")
    assert first != second
    assert {event.assessment for event in store.current_events()} == {second}
    assert store.current_feedback() == []
    store.switch_assessment(0)
    assert {event.assessment for event in store.current_events()} == {first}
    assert [entry.text for entry in store.current_feedback()] == ["keep it read-only"]
    # the session-wide trail still holds every row
    assert len(store.list_events()) > len(store.current_events())


# --- gap 5: a model reply that arrives after the operator moved on -------------------------
async def test_a_late_model_reply_never_lands_in_another_run(app, model_active, monkeypatch):
    from reconix.llm import client

    answer_now = threading.Event()

    def blocking_complete(*args, **kwargs):
        answer_now.wait(5)
        return "The first run is where the three findings are."

    monkeypatch.setattr(client, "complete", blocking_complete)
    run_to("scope")
    store.new_assessment()
    store.start_run("scan 10.0.0.0/24 for open ports")
    store.switch_assessment(0)

    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.agent_mode = False                       # the scripted chat path, not the agent
        assert app.submit_request("what did you find so far?")
        await settle(pilot)
        app.switch_assessment(1)                     # the operator moves on, mid-answer
        await settle(pilot)
        answer_now.set()
        for _ in range(12):
            await settle(pilot)
        assert all("three findings" not in entry.text for entry in store.list_chat())
        store.switch_assessment(0)
        assert all("three findings" not in entry.text for entry in store.list_chat())


# --- gap 6: the list getters return copies ------------------------------------------------
def test_the_list_getters_return_copies():
    run_to(None)
    finding = store.list_findings()[0]
    finding.title = "changed"
    finding.evidence.append("changed")
    assert store.list_findings()[0].title != "changed"
    assert "changed" not in store.get_finding(finding.fid).evidence

    one = store.get_finding(finding.fid)
    one.status = "fixed"
    assert store.get_finding(finding.fid).status == "open"

    store.list_activity()[0].message = "changed"
    assert store.list_activity()[0].message != "changed"

    store.list_events()[0].detail = "changed"
    assert store.list_events()[0].detail != "changed"

    store.list_assessments()[0].label = "changed"
    assert store.list_assessments()[0].label != "changed"

    # the store still writes through its own rows
    store.triage_finding(finding.fid, status="fixed")
    assert store.get_finding(finding.fid).status == "fixed"


# --- gap 7: an open HIGH confirmation does not survive a switch ---------------------------
async def test_an_old_high_token_is_refused_after_switching_back(app):
    run_to("scope")
    decide("scope")
    gate = high_gate()
    request = store.get_approval(gate.split(":", 1)[1])
    token = store.request_confirmation(request.request_id, request.command_hash)
    store.new_assessment()
    store.switch_assessment(0)                       # back on the HIGH gate, token still live

    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.switch_assessment(1)                     # leaving the run: its token is voided
        await settle(pilot)
        app.switch_assessment(0)
        await settle(pilot)
        assert store.waiting_gate() == gate and store.gate_state(gate) == "pending"
        with pytest.raises(store.StoreValidationError):
            store.approve(request.request_id, command_hash=request.command_hash,
                          confirmation_token=token)
        assert store.decision_for(request.request_id) is None
        assert store.request_confirmation(request.request_id, request.command_hash) != token
