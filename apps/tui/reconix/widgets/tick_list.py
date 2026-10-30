"""A Claude Code-style tick list: Space ticks a row, Enter saves, Esc cancels.

Used by the step chat for the scope's ports and tools. The rows and what starts ticked come
from the store (`answer_scope_change`); this widget only reports what the operator ticked.
"""

from typing import List, Sequence, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import SelectionList, Static
from textual.widgets.selection_list import Selection

from .. import theme


class _Ticks(SelectionList):
    """A SelectionList where Enter saves (Space still ticks)."""

    BINDINGS = [
        Binding("enter", "save", "save", show=False),
        Binding("escape", "cancel", "cancel", show=False),
    ]

    def action_save(self) -> None:
        self.parent.post_message(TickList.Saved(self.parent, self.selected))

    def action_cancel(self) -> None:
        self.parent.post_message(TickList.Cancelled(self.parent))


class TickList(Vertical):
    """Ports and tools to tick. Posts `Saved(ports, tools)` or `Cancelled`."""

    class Saved(Message):
        def __init__(self, tick_list: "TickList", values: List[str]) -> None:
            super().__init__()
            self.tick_list = tick_list
            self.ports = [int(v[5:]) for v in values if v.startswith("port:")]
            self.tools = [v[5:] for v in values if v.startswith("tool:")]

    class Cancelled(Message):
        def __init__(self, tick_list: "TickList") -> None:
            super().__init__()
            self.tick_list = tick_list

    def __init__(
        self,
        ports: Sequence[Tuple[int, bool]],
        tools: Sequence[Tuple[str, bool]],
        *,
        id: str = "tick-list",
    ) -> None:
        super().__init__(id=id, classes="tick-list")
        self._ports = list(ports)
        self._tools = list(tools)

    def compose(self) -> ComposeResult:
        what = "ports and tools" if self._ports else "tools"
        yield Static(Text(f"Allowed {what}", style=f"bold {theme.TEXT}"))
        rows: List[Selection] = [
            Selection(Text(f"port  {port}"), f"port:{port}", ticked) for port, ticked in self._ports
        ] + [
            Selection(Text(f"tool  {tool}"), f"tool:{tool}", ticked) for tool, ticked in self._tools
        ]
        yield _Ticks(*rows, id="tick-rows")
        yield Static(
            Text("Space tick · Enter save · Esc cancel", style=theme.DIM), classes="menu-hint"
        )

    def on_mount(self) -> None:
        self.query_one(_Ticks).focus()
