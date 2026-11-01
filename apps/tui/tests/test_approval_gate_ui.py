"""The approval gate through the screens: the "N of M" count, the disabled Edit, the HIGH
double-check against stray keys, a blocked vs. an allowed edit, secrets masked on screen, and
a quick reject / decide-later regression. The store stays the authority throughout."""

import io

import pytest
from textual._time import get_time
from textual.widgets import Input, Static

from reconix import store
from reconix.screens import ApprovalScreen, ChoiceScreen, ExecutionScreen
from reconix.screens.forms import ApprovalEditForm
from reconix.store import lists
from reconix.store.approvals import command_digest
from reconix.widgets import ChoiceMenu

from .support import SIZE, event_kinds, run_ui_to, screen_text, settle

FIRST, SECOND = "approval-001", "approval-002"

# Three secret shapes store/redact.py masks; each distinctive value must never reach the screen.
TOKEN, BEARER, PASSWORD = "TKNsecrettoken0value", "BRRsecretbearer1value", "PWDsecretpass2value"
SECRET_COMMAND = (f"GET https://shop.example.com/api/orders/10483?token={TOKEN} "
                  f"-H 'Authorization: Bearer {BEARER}' password={PASSWORD}")
SECRETS = (TOKEN, BEARER, PASSWORD)
MASKED_NOTE = "secrets masked on screen"


def rendered(screen, width: int = 400) -> str:
    """Every Static's content as plain text, wide enough that nothing wraps (so a secret that
    was *not* masked would show up whole, never split across lines)."""
    from rich.console import Console

    out = []
    for static in screen.query(Static):
        console = Console(file=io.StringIO(), width=width, force_terminal=False)
        console.print(static.content)
        out.append(console.file.getvalue())
    return "\n".join(out)


def inject_secret(request_id: str) -> None:
    """Put a secret into the live request's command and re-bind its (real) hash, the way an
    edited value or a crafted template could. The path stays clean, so the policy still allows
    it and approve() with the real hash still works."""
    request = store.get_approval(request_id)
    request.command = SECRET_COMMAND
    request.command_hash = command_digest(request.command)


# --- the panel ------------------------------------------------------------------------------
async def test_gated_action_count_is_shown_and_correct(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        assert "gated action 1 of 2 requires your approval" in rendered(app.screen)
        await pilot.press("1")                                   # approve the MEDIUM one
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert "gated action 2 of 2 requires your approval" in rendered(app.screen)


async def test_edit_is_disabled_without_a_param_label(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        store.get_approval(FIRST).param_label = ""               # nothing left to edit
        app.reload_screen()
        await settle(pilot)
        menu = app.screen.query_one("#approval-menu", ChoiceMenu)
        edit = next(choice for choice in menu._choices if choice.id == "edit")
        assert edit.disabled
        await pilot.press("4")                                   # a disabled choice can't be picked
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)


# --- the HIGH second confirmation -----------------------------------------------------------
async def test_high_dialog_ignores_digits_and_an_early_enter(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{SECOND}")
        await pilot.press("1")                                   # Approve & run → the double check
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        menu = app.screen.query_one("#dialog-menu", ChoiceMenu)
        menu._armed_at = get_time() + 100                        # not armed yet (ARM_DELAY is 0)
        for key in ("enter", "1", "2", "3", "9"):
            await pilot.press(key)
            await settle(pilot)
            assert isinstance(app.screen, ChoiceScreen)          # still waiting; nothing was chosen
            assert not store.is_approved(SECOND)


async def test_escape_voids_the_confirmation_token(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{SECOND}")
        request = store.get_approval(SECOND)
        await pilot.press("1")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        assert "approval.confirmation_requested" in event_kinds()
        token = lists.current().confirmations[-1].token
        await pilot.press("escape")                              # leave without approving
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert "approval.confirmation_declined" in event_kinds()
        assert not store.is_approved(SECOND)
        with pytest.raises(store.StoreValidationError):          # the voided token is refused
            store.approve(SECOND, command_hash=request.command_hash, confirmation_token=token)


# --- editing where the action runs ----------------------------------------------------------
async def test_a_blocked_edit_leaves_the_hash_unchanged(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        before = store.get_approval(FIRST).command_hash
        await pilot.press("4")
        await settle(pilot)
        assert isinstance(app.screen, ApprovalEditForm)
        app.screen.query_one("#param", Input).value = "/admin/users"
        app.screen.query_one("#submit").press()
        await settle(pilot)
        assert isinstance(app.screen, ApprovalEditForm)          # the form stays open
        assert "Blocked by policy" in screen_text(app.screen)
        assert store.get_approval(FIRST).command_hash == before


async def test_an_allowed_edit_gives_a_new_hash_and_voids_the_old(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{SECOND}")
        old_hash = store.get_approval(SECOND).command_hash
        old_token = store.request_confirmation(SECOND, old_hash)
        store.edit_approval(SECOND, "/api/orders/10499")
        new = store.get_approval(SECOND)
        assert new.command_hash != old_hash
        app.reload_screen()
        await settle(pilot)
        assert new.command in rendered(app.screen)               # the panel shows the new request
        with pytest.raises(store.StoreValidationError):          # the old hash is refused
            store.approve(SECOND, command_hash=old_hash, confirmation_token=old_token)
        with pytest.raises(store.StoreValidationError):          # the old token is refused too
            store.approve(SECOND, command_hash=new.command_hash, confirmation_token=old_token)
        fresh = store.request_confirmation(SECOND, new.command_hash)
        store.approve(SECOND, command_hash=new.command_hash, confirmation_token=fresh)
        assert store.is_approved(SECOND)


# --- secrets never render -------------------------------------------------------------------
async def test_a_secret_in_the_command_is_never_shown_but_approval_still_works(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{SECOND}")
        inject_secret(SECOND)
        real_hash = store.get_approval(SECOND).command_hash      # of the real, unmasked command
        app.reload_screen()
        await settle(pilot)

        panel = rendered(app.screen)                             # the gated-action panel
        assert all(secret not in panel for secret in SECRETS)
        assert MASKED_NOTE in panel

        await pilot.press("4")                                   # the Edit form note is masked…
        await settle(pilot)
        form = app.screen
        assert isinstance(form, ApprovalEditForm)
        assert all(secret not in rendered(form) for secret in SECRETS)
        assert form.query_one("#param", Input).value == store.get_approval(SECOND).path  # …but real
        await pilot.press("escape")
        await settle(pilot)

        await pilot.press("3")                                   # the Details view is masked
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        assert all(secret not in rendered(app.screen) for secret in SECRETS)
        await pilot.press("enter")                               # Back to the choices
        await settle(pilot)

        await pilot.press("1")                                   # the HIGH confirmation is masked
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        assert all(secret not in rendered(app.screen) for secret in SECRETS)
        await pilot.press("down", "enter")                       # Yes, run it (No is the default)
        await settle(pilot)
        assert store.is_approved(SECOND)
        decision = store.decision_for(SECOND)
        assert decision.command_hash == real_hash                # approved against the real request


async def test_a_clean_request_shows_no_masked_note(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{SECOND}")        # the scripted demo, no secrets
        assert MASKED_NOTE not in rendered(app.screen)           # the panel
        await pilot.press("1")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        assert MASKED_NOTE not in rendered(app.screen)           # the HIGH confirmation body


# --- reject and decide later (regression) ---------------------------------------------------
async def test_decide_later_pauses_then_reject_stops_the_run(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        await pilot.press("escape")                              # decide later
        await settle(pilot)
        assert isinstance(app.screen, ExecutionScreen)
        assert store.waiting_gate() == f"approval:{FIRST}"
        assert store.decision_for(FIRST) is None
        await pilot.press("enter")                               # back to the decision
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        await pilot.press("2")                                   # Reject
        await settle(pilot)
        assert isinstance(app.screen, ExecutionScreen)
        assert store.is_finished() and not store.is_completed()
