---
name: add-widget
description: How to create or extract a reusable widget in tui/reconix/widgets/ for the Reconix TUI. Use when the same markup or layout appears on two or more screens, or when building a new UI component (panel, badge row, key-value list, log view).
---

# Add a reusable TUI widget

## When
- The same markup, layout or behaviour appears on two or more screens.
- A screen's `compose_body()` grows past about 60 lines because of one repeated block.

## Steps
1. **Pick a file by concern** in `tui/reconix/widgets/` (`chrome.py`, `findings.py`,
   `manifest.py`, …). Do not grow one catch-all module.
2. **Write the widget**, matching an existing one (`widgets/chrome.py`, `widgets/question.py`):
   - Module and class docstrings; type hints; Python 3.9 compatible.
   - Take data through `__init__` arguments; never read the store for content the caller
     should pass.
   - Colors from `theme.*`; layout and spacing in `reconix.tcss` with the class as selector.
   - Recompute width-dependent rendering in `on_resize`.
   - Untrusted text (user, tool, scope, backend) goes in as `rich.text.Text`, never markup.
3. **Export** it from `tui/reconix/widgets/__init__.py` (import and `__all__`).
4. **Replace every duplicate** with the widget in the same change.
5. **Verify**: `python -m compileall -q reconix && pytest -q` (from `tui/`).

## Skeleton

```python
"""<What this widget is for>."""

from rich.text import Text
from textual.widgets import Static

from .. import theme


class KeyValueRow(Static):
    """A dim label followed by a value, aligned in a fixed column."""

    def __init__(self, label: str, value: str, color: str = theme.TEXT, width: int = 12) -> None:
        line = Text(f"{label:<{width}}", style=theme.DIM)
        line.append(value, style=color)      # value may be untrusted: appended as plain text
        super().__init__(line)
```
