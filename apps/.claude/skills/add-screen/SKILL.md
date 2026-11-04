---
name: add-screen
description: Checklist for adding a new screen (flow frame or overlay) to the Reconix TUI so it is wired into navigation, bindings, help and docs correctly. Use whenever creating a new file under tui/reconix/screens/.
---

# Add a screen to the Reconix TUI

All paths are under `tui/`. Run commands from `tui/` with its `.venv` active.

## 1. Plan (write it down before coding)
- Screen key (`flow_name`), footer chip (`mode_name`), and its position in `FLOW`.
- Data it needs, and whether those fields exist in `reconix/models/` and `reconix/store/`.
- Bindings: primary (`enter`), back (`escape`), plus screen-specific keys.
- Reusable pieces: existing widgets, or new widgets to extract (`add-widget`).

## 2. Data first
Add dataclasses to `reconix/models/`, read/decide functions to the matching
`reconix/store/<resource>.py`, exported from `store/__init__.py`. Every decision validates in
the store and raises `StoreValidationError`. Screens hold no data literals.

## 3. Create `reconix/screens/<name>.py`

```python
"""Frame NN — <Human name>."""

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Static

from .. import store, theme
from .base import ReconixScreen


class <Name>Screen(ReconixScreen):
    flow_name = "<name>"
    mode_name = "<MODE>"
    # scroll = False   # only if the body should fill instead of scroll

    BINDINGS = [
        Binding("enter", "next", "continue"),
        Binding("escape", "prev", "back", show=False),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="panel") as panel:
            panel.border_title = Text("◆ TITLE")      # never a markup string
            yield Static(Text(store.<getter>().name))  # user/tool text: Text, not markup
```

A screen whose layout depends on the run returns that state from `view_state()`; small
per-step updates go in `refresh_live()`.

A question to the operator uses the `Question` widget (handle `ChoiceMenu.Chosen`, add
`Binding("enter", "choose", show=False)`). Pop-ups use `ChoiceScreen`, opened by the app with
`app.open_dialog(dialog, callback)`; risky ones (`danger=True`) default to the safe choice.
Unavailable options are `Choice(..., disabled=True)`: no dead ends.

## 4. Wire it up
- [ ] Export from `reconix/screens/__init__.py` (import and `__all__`).
- [ ] Add it to `FLOW` in `reconix/shell/navigation.py`, in order.
- [ ] Add or renumber the `1…N` jump bindings in `reconix/app.py`.
- [ ] Gate routing, if a gate opens it: `reconix/flow/gates.py`.
- [ ] Styles in `reconix/reconix.tcss` with `$tokens` only.
- [ ] Every binding has a description; update `screens/help.py` and `tui/README.md`. Add a
      `/command` in `reconix/commands/builtin.py` if it should be reachable by name, then run
      `python scripts/export_commands.py` (the web docs' command list).
- [ ] A HIGH-risk action goes through the approval gate.

## 5. Verify
```bash
python -m compileall -q reconix
python -c "from reconix.app import ReconixApp"
pytest -q        # add a navigation test for the new screen (write-tui-test)
```
