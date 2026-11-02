"""The plan's rows, drawn the same on the Plan screen and in the step chat.

`plan_line` draws one row (number, label, what it does; then risk, gate and status).
`PlanPanel` is the ▤ PLAN card: every row of the plan in a bordered panel, as the step
chat shows it when you ask for the plan or change its order.
"""

from typing import Sequence

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static

from .. import theme
from ..models import PlanRow

GATE_NOTE = {"auto": "runs automatically", "login": "asks for the target login",
             "approve": "needs your approval"}
STATUS_NOTE = {"done": ("✓ done", theme.GREEN), "active": ("◌ now", theme.CYAN),
               "rejected": ("✕ rejected", theme.CRITICAL), "pending": ("· pending", theme.DIM)}
MISSING = "—"
NUM_WIDTH = 4             # " 3a " before the label
LABEL_WIDTH = 30


def fit(text: str, width: int) -> str:
    """`text` cut to `width` characters with "…" (unchanged when it fits or width <= 0)."""
    if width <= 0 or len(text) <= width:
        return text
    return text[:max(width - 1, 0)] + "…"


def plan_line(row: PlanRow, width: int = 0, full: bool = False) -> Text:
    """Two lines per row: number, label and what it does; then risk, gate and status.

    With `width` (the list's inner width) a long label or command is cut with "…" so the
    row never wraps; `full` (the highlighted row) shows it whole. A missing value shows as
    "—" and an unknown status as its own text: nothing is made up.
    """
    label = row.label or MISSING
    what = f"$ {row.command}" if row.command else (row.detail or "")
    if width and not full:
        label = fit(label, LABEL_WIDTH - 1)
        what = fit(what, width - NUM_WIDTH - LABEL_WIDTH)
    line = Text()
    line.append(f" {row.num or MISSING:<3}", style=f"bold {theme.MUTED}")
    line.append(f"{label:<{LABEL_WIDTH}}", style=f"bold {theme.TEXT}")
    line.append(what, style=theme.TEAL if row.command else theme.MUTED)
    line.append("\n     ")
    risk = row.risk or MISSING
    line.append(f"● {risk}", style=f"bold {theme.RISK.get(risk, theme.MUTED)}")
    gate_color = theme.MEDIUM if row.gate not in ("auto", "") else theme.DIM
    line.append(f"   {GATE_NOTE.get(row.gate, row.gate or MISSING)}", style=gate_color)
    note, color = STATUS_NOTE.get(row.status, (f"· {row.status or MISSING}", theme.DIM))
    line.append(f"   {note}", style=color)
    return line



class PlanPanel(Vertical):
    """The ▤ PLAN card: all rows in order, each shown in full."""

    def __init__(self, rows: Sequence[PlanRow], subtitle: str = "", **kwargs) -> None:
        super().__init__(classes="panel accent", **kwargs)
        self.border_title = "▤ PLAN"
        self.border_subtitle = subtitle
        self._rows = list(rows)

    def compose(self) -> ComposeResult:
        text = Text()
        for i, row in enumerate(self._rows):
            if i:
                text.append("\n")
            text.append_text(plan_line(row, full=True))
        yield Static(text if self._rows else Text("No plan yet.", style=theme.MUTED),
                     classes="panel-body")
