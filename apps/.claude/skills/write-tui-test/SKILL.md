---
name: write-tui-test
description: Patterns for testing the Reconix TUI with pytest, pytest-asyncio and Textual's App.run_test()/Pilot, including navigation, menus, the slash-command prompt, the approval gate and dialogs. Use when writing, fixing or extending tests under tui/tests/.
---

# Testing the Reconix TUI

Run from `tui/` with the `.venv` active: `pytest -q`, one file `pytest -q tests/test_x.py`,
one test `pytest -q tests/test_x.py::test_name` or `-k approval`.

## Harness (already set up)
- `asyncio_mode = "auto"`: `async def test_…(app)` needs no marker.
- `tests/conftest.py` (autouse): resets the store around every test, plays runs instantly
  (`RunController.SPEED = 0`), points reports / saved copies / LLM and knowledge files at temp
  folders, and stubs the browser (`opened` fixture records URLs) and the web launcher
  (`web_launches`). Never launch a real browser, dashboard or network call.
- `tests/support.py`:
  - `SIZE` (always pass `size=SIZE`), `TEST_PASSWORD` (must never appear in output),
    `ASK_REQUEST` (stops at the template gate; `store.DEMO_REQUEST` skips it).
  - Store drivers: `run_to(gate)`, `decide(gate)`, `play_until_gate()`, `run_to_end()`,
    `event_kinds()`.
  - UI drivers: `run_ui_to(app, pilot, gate)`, `pass_gate(app, pilot)`, `show(app, pilot, name)`,
    `start_demo(pilot)`, `type_request(pilot, text)`, `settle(pilot)` (dialogs open on the
    app's next turn), `wait_until(pilot, cond)`, `screen_text(screen)`.

## Patterns

**Store rule** (fast, no UI; see `tests/test_store_gates.py`):
```python
import pytest

from reconix import store
from .support import run_to

HIGH = "approval-002"                             # the demo run's HIGH-risk approval

def test_a_high_token_works_once_and_only_for_its_hash():
    run_to(f"approval:{HIGH}")                    # gates are "template", "scope", "plan",
    high = store.get_approval(HIGH)               #   "approval:<id>", "account", "code"
    token = store.request_confirmation(HIGH, high.command_hash)
    with pytest.raises(store.StoreValidationError):
        store.approve(HIGH, command_hash="sha256:other", confirmation_token=token)
    store.approve(HIGH, command_hash=high.command_hash, confirmation_token=token)
```

**Screen flow**:
```python
from reconix.screens import ApprovalScreen
from .support import SIZE, run_ui_to, settle

async def test_high_risk_asks_twice(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "approval:approval-002")   # the HIGH-risk one
        assert isinstance(app.screen, ApprovalScreen)
        depth = len(app.screen_stack)
        ...                                          # press keys, then:
        await settle(pilot)
        assert len(app.screen_stack) == depth        # every dialog path restores the stack
```

Check the exact helper and store names in `tests/support.py` and `reconix/store/__init__.py`
before using them; copy the closest existing test file.

## Rules
- After key presses that switch screens or open dialogs, `await settle(pilot)` /
  `pilot.pause()`. Never `time.sleep`.
- `run_test` turns notifications off: assert on screens, store state, focus and regions.
- A test for anything shown or saved asserts `TEST_PASSWORD` is absent.
- A bug fix comes with a test that fails before the fix. Report the real pytest output.
