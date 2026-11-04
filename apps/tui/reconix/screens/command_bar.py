"""Command bar: press `/` on any screen to run a slash command."""

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen

from .. import store
from ..commands import COMMANDS
from ..widgets import PromptBox
from .start import length_error, target_error


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
        refusal = self.app.login_blocks(event.text)
        if refusal is not None:      # the target login: the line may be the password
            event.box.show_error(refusal)
            return
        if self.app.is_path_line(event.text):
            # A local path is a target: the Start prompt's checks first (a missing folder
            # stays here), then the app takes it like a line typed at the Start prompt.
            text = event.text.strip()
            error = length_error(text)
            if not error and not store.get_run().started and store.looks_like_target(text):
                error = target_error(text)
            if error:
                event.box.show_error(error)
                return
            self.dismiss(event.text)
            return
        check = self.app.check_command(event.text)
        if not check.ok:
            event.box.show_error(check.error)    # one line under the input, until you type
            return
        self.dismiss(event.text)

    def on_prompt_box_submitted(self, event: PromptBox.Submitted) -> None:
        event.stop()
        if event.text:
            event.box.show_error("Commands start with / — type / to see them.")
        else:
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)
