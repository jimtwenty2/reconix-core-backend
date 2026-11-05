"""The help overlay: its "Everywhere" map matches the app's keys, and it only shows keys."""

from reconix import store
from reconix.app import ReconixApp
from reconix.screens import ApprovalScreen, HelpScreen
from reconix.screens.help import GLOBAL_ROWS

from .support import SIZE, settle


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


def test_everywhere_rows_match_the_app_bindings(app):
    bindings = ReconixApp.BINDINGS
    jumps = [b.key for b in bindings if b.action.startswith("jump(")]
    # On Alt, never a bare digit: a menu's digits pick a choice (QA-008)
    assert jumps == [f"alt+{n}" for n in range(1, len(jumps) + 1)]
    labels = [keys for keys, _ in GLOBAL_ROWS]
    assert f"Alt+1 … {len(jumps)}" in labels

    shown = {app.get_key_display(b).upper() for b in bindings}
    for b in bindings:                                    # every app key is in the map …
        if not b.key.startswith("alt+"):
            assert app.get_key_display(b).upper() in " ".join(labels).upper(), b.key
    for keys in labels:                                   # … and every key in it is real
        for key in keys.replace("…", " ").split():
            assert key.upper() in shown or key.isdigit(), keys


async def test_keys_pressed_under_help_never_reach_the_gate(app):
    async with app.run_test(size=SIZE) as pilot:
        gate = await ui_to_approval(app, pilot)
        await pilot.press("question_mark")
        await settle(pilot)
        assert isinstance(app.screen, HelpScreen)

        await pilot.press("enter", "1", "2", "3", "8")
        await settle(pilot)
        assert isinstance(app.screen, HelpScreen)
        assert store.waiting_gate() == gate

        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert store.waiting_gate() == gate
