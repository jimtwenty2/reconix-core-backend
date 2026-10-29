"""Command bar: press `/` on any screen to run a slash command."""

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen

from .. import store
from ..commands import COMMANDS, find, parse
from ..widgets import PromptBox


class CommandBarScreen(ModalScreen[Optional[str]]):
    """Dismisses with the command line to run; the app runs it after the bar closes.

    Running it from inside the bar would break: switching screens under a modal
    drops the modal's callback.
    """

    BINDINGS = [Binding("escape", "close", "close")]

    def compose(self) -> ComposeResult:
        with Vertical(id="command-bar"):
            yield PromptBox(
                COMMANDS, store.list_history, initial="/",
                placeholder="Type a command, e.g. /plan", id="command-box",
            )

    def on_mount(self) -> None:
        self.query_one(PromptBox).focus_input()

    def on_prompt_box_command_submitted(self, event: PromptBox.CommandSubmitted) -> None:
        event.stop()
        if self is not self.app.screen:
            return                   # a second Enter queued before the bar closed
        name, _ = parse(event.text)
        # A local path (/home/me/app) is not a command: the app takes it as a target.
        if find(COMMANDS, name) is None and "/" not in name:
            self.notify(f"Unknown command /{name} — pick one from the list.",
                        severity="warning", markup=False)
            return
        self.dismiss(event.text)

    def on_prompt_box_submitted(self, event: PromptBox.Submitted) -> None:
        event.stop()
        if event.text:
            self.notify("Commands start with / — type / to see them.", severity="warning")
        else:
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)
