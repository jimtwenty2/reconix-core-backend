"""Reconix TUI — main application.

An interactive, keyboard-first demo of the Reconix security-testing flow, built with
Textual. One screen per step: Start → Template → Plan → Approval → Execution → Findings →
Detail → Report. The assessment run (reconix/store, played by flow.RunController) keeps
going while you move between screens and stops at each gate until you decide. Navigate
with the arrow keys and Enter, type `/` for commands, and press `?` for the keys.

The app's behaviour lives in `reconix/shell/` (navigation, run hosting, actions, dialogs);
this module wires it together.
"""

import sys
from typing import Dict, Optional

from textual.app import App
from textual.binding import Binding

from . import store, theme
from .commands import COMMANDS, Command, CommandCheck, check_command_line, find, parse
from .models import Choice
from .screens import ChoiceScreen, CommandBarScreen, HelpScreen, StartScreen
from .shell import (
    ActionsMixin,
    DialogsMixin,
    KnowledgeMixin,
    LlmMixin,
    NavigationMixin,
    RunHostMixin,
    WebDashboardMixin,
)
from .widgets import ActivityStatus, RunLog, SessionBar


class ReconixApp(
    NavigationMixin,
    RunHostMixin,
    ActionsMixin,
    DialogsMixin,
    KnowledgeMixin,
    LlmMixin,
    WebDashboardMixin,
    App,
):
    """Reconix — AI-Powered Security Testing Assistant (demo)."""

    CSS_PATH = "reconix.tcss"
    TITLE = "reconix"
    ENABLE_COMMAND_PALETTE = False  # Reconix has its own "/" command system

    # Poll the Core API's health so the header shows whether the backend is reachable.
    # Tests opt in (see conftest) so they don't spawn background health workers.
    CHECK_CORE_API_ON_START = True
    CORE_API_POLL_SECONDS = 15

    BINDINGS = [
        Binding("right", "nav_next", "next", show=False),
        Binding("left", "nav_prev", "back", show=False),
        # "/" stays non-priority so a focused Input still receives it as text.
        Binding("slash", "command_bar", "commands", key_display="/"),
        Binding("question_mark", "help", "help", key_display="?"),
        Binding("ctrl+q", "quit", "quit"),
        # Priority, so Ctrl+C stops a run (it asks first) on every flow screen, also with the
        # Start prompt focused; in a dialog or a field with selected text it is left to them.
        Binding("ctrl+c", "stop_assessment", "stop", show=False, priority=True),
        Binding("ctrl+o", "toggle_activity", "expand steps", show=False),
        Binding("ctrl+y", "copy_selection", "copy", show=False),
        # Quick jumps for presenting — hidden to keep the footer clean. On Alt, never on a
        # bare digit: a menu's digits pick a choice, and the same key must not mean "show
        # me screen N" on one screen and "decide this gate" on the next (QA-008).
        Binding("alt+1", "jump('start')", "start", show=False),
        Binding("alt+2", "jump('template')", "template", show=False),
        Binding("alt+3", "jump('plan')", "plan", show=False),
        Binding("alt+4", "jump('approval')", "approval", show=False),
        Binding("alt+5", "jump('execution')", "execution", show=False),
        Binding("alt+6", "jump('findings')", "findings", show=False),
        Binding("alt+7", "jump('detail')", "detail", show=False),
        Binding("alt+8", "jump('report')", "report", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.selected_finding: str = ""  # finding id shown on the Detail screen
        self.pending_prompt: str = ""  # draft for the Start prompt ("Chat about this")
        self.template_pick: Optional[str] = None  # template chosen with /template <id>
        self.findings_filter: str = "all"  # Findings list view (kept across screens)
        self.findings_sort: str = "severity"
        self.activity_expanded = False  # Ctrl+O: list the steps Reconix finished
        self._init_run_host()
        self._init_web()

    def get_css_variables(self) -> Dict[str, str]:
        # The stylesheet's $variables come from theme.py, the one place colors are defined.
        return {**super().get_css_variables(), **theme.CSS_TOKENS}

    KALI_POLL_SECONDS = 15  # how often the top bar's kali chip refreshes from the Core API

    def on_mount(self) -> None:
        self.push_screen(StartScreen())
        self.call_after_refresh(self.ask_provider_on_start)  # until a model is active
        if self.CHECK_CORE_API_ON_START:
            self.poll_core_api()
            if self.CORE_API_POLL_SECONDS > 0:
                self.set_interval(self.CORE_API_POLL_SECONDS, self.poll_core_api)

    def poll_core_api(self) -> None:
        """Check the Core API's health in the background and show it in the header."""

        def work() -> None:
            from .core_api import client

            self.from_worker(self._core_api_status, client.health())

        self.run_worker(work, thread=True, group="core-api-health", exit_on_error=False)

    def _core_api_status(self, online: bool) -> None:
        if store.api_online() == online:
            return
        store.set_api_online(online)
        for bar in self.screen.query(SessionBar):
            bar.refresh_line()

    def on_unmount(self) -> None:
        # Quitting ends the session: mark the saved copies so the web dashboard shows an
        # unfinished run as interrupted rather than still waiting.
        self.controller.stop()
        self.stop_web_dashboard()
        store.close_session()

    # --- global keys ---------------------------------------------------------------------------
    def action_help(self) -> None:
        if isinstance(self.screen, HelpScreen):
            self.pop_screen()
        else:
            self.push_screen(HelpScreen.for_screen(self.screen))

    def action_copy_selection(self) -> None:
        """Ctrl+Y: copy the selected text (drag to select) to the clipboard. Ctrl+C is Stop,
        so copy is its own key. Paste works in any input."""
        text = self.screen.get_selected_text()
        if text:
            self.copy_to_clipboard(text)
            self.notify(f"Copied {len(text)} characters.", title="Clipboard", timeout=2)
        else:
            self.notify(
                "Select text first (drag with the mouse), then Ctrl+Y.", title="Copy", timeout=3
            )

    def action_toggle_activity(self) -> None:
        self.activity_expanded = not self.activity_expanded
        for status in self.screen.query(ActivityStatus):
            status.set_expanded(self.activity_expanded)
        for log in self.screen.query(RunLog):  # the live output's thinking blocks
            log.set_expanded(self.activity_expanded)

    def action_command_bar(self) -> None:
        self.open_dialog(CommandBarScreen(), self._on_command_bar)

    def show_doctor(self) -> None:
        """Show TUI-safe installation diagnostics without blocking the event loop."""
        from .doctor import run_diagnostics

        self.notify("Running Reconix Doctor…", markup=False)

        def work() -> None:
            report = run_diagnostics(include_local_services=False)
            self.from_worker(self._doctor_done, report)

        self.run_worker(work, thread=True, group="doctor", exit_on_error=False)

    def _doctor_done(self, report) -> None:
        """Open the completed doctor report on the UI thread."""
        from .doctor import report_lines

        self.open_dialog(
            ChoiceScreen(
                "◆ RECONIX DOCTOR",
                "Installation and health checks",
                [Choice("close", "Close")],
                body=report_lines(report),
                chip="/doctor",
            )
        )

    def _on_command_bar(self, line: Optional[str]) -> None:
        if line:  # runs after the bar has closed
            self.run_command_line(line)

    # --- slash commands ------------------------------------------------------------------------
    def check_command(self, text: str) -> CommandCheck:
        """Is `/name [arg]` a command that can run, with a fitting argument? Runs nothing."""
        return check_command_line(COMMANDS, text, self)

    @staticmethod
    def is_path_line(text: str) -> bool:
        """`/home/me/app` is a local path, not a command (its "name" holds a slash)."""
        return "/" in parse(text)[0]

    # At the target login a typed line may be the password: only these, with no argument.
    LOGIN_COMMANDS = ("stop", "new", "help", "quit")

    def login_blocks(self, text: str) -> Optional[str]:
        """Why `text` can't run while the run waits for (or stopped at) the target login, or
        None. Only /stop, /new, /help and /quit with no argument pass; anything else may be
        the password, so it is never run, echoed or kept in the history."""
        refusal = store.login_refusal()
        if refusal is None:
            return None
        name, arg = parse(text)
        command = None if self.is_path_line(text) else find(COMMANDS, name)
        if command is not None and command.name in self.LOGIN_COMMANDS and arg is None:
            return None
        return refusal

    def run_command_line(self, text: str) -> bool:
        """Run `/name [arg]`. Returns False (and warns) when the line can't run."""
        refusal = self.login_blocks(text)
        if refusal is not None:
            self.notify(refusal, severity="warning", markup=False)
            return False
        if self.is_path_line(text):
            return self.submit_request(text)
        check = self.check_command(text)
        if not check.ok:
            self.notify(check.error, severity="warning", markup=False)
            return False
        self.run_checked(text, check)
        return True

    def run_checked(self, text: str, check: CommandCheck) -> None:
        """Run a line `check_command` already passed (kept in the history like the bar's)."""
        refusal = self.login_blocks(text)
        if refusal is not None:  # never run, echoed or kept at the target login
            self.notify(refusal, severity="warning", markup=False)
            return
        self._remember(text)
        self.run_command(check.command, check.arg)

    def run_command(self, command: Command, arg: Optional[str] = None) -> None:
        """Run a command; if it needs a choice that wasn't typed, ask with a menu."""
        if command.choices is None or not command.ask:
            command.run(self, arg)
            return
        choices = command.choices(self)
        if arg and arg.lower() in {c.id for c in choices}:
            command.run(self, arg.lower())
            return
        if not choices:
            self.notify(command.empty or "Nothing to choose from yet.", severity="warning")
            return

        def chosen(choice_id: Optional[str]) -> None:
            if choice_id:
                command.run(self, choice_id)

        question = command.question or command.description
        self.open_dialog(
            ChoiceScreen(command.description, question, choices, chip=f"/{command.name}"),
            chosen,
        )


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1].lower() == "doctor":
        from .doctor import doctor_main

        raise SystemExit(doctor_main())
    ReconixApp().run()


if __name__ == "__main__":
    main()
