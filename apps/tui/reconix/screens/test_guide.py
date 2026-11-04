"""/tests — the evaluator's checklist: every flow and case, with Pass / Fail / Skip marks.

An overlay (like the help), so it never changes the assessment underneath. The cases come
from `store.test_guide` (the same data the docs in docs/evaluator/ are written from); marks
and notes are saved at once to the results folder, and `e` exports a Markdown + JSON report.
"""

from typing import List, Optional, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from .. import theme
from ..store import StoreValidationError, test_guide
from ..store.test_guide import Case, Flow, Result
from .forms.test_note import TestNoteForm

MARK_STYLE = {
    "PASS": f"bold {theme.GREEN}",
    "FAIL": f"bold {theme.CRITICAL}",
    "SKIP": f"bold {theme.MUTED}",
    "": theme.DIM,
}
MARK_LABEL = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP", "": "····"}


class TestGuideScreen(ModalScreen):
    """The checklist. Dismisses with nothing; the results are already saved."""

    __test__ = False  # not a pytest test class

    BINDINGS = [
        Binding("p", "mark('PASS')", "pass"),
        Binding("f", "mark('FAIL')", "fail"),
        Binding("s", "mark('SKIP')", "skip"),
        Binding("n", "note", "note"),
        Binding("e", "export", "export results"),
        Binding("escape", "close", "close"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._flows: Tuple[Flow, ...] = test_guide.list_flows()
        self._results = test_guide.results.load()
        self._ids: List[str] = []  # option index -> case id ("" = a flow header)

    # --- layout ---------------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        with Vertical(id="tests-box") as box:
            box.border_title = "✓ Test guide · /tests"
            yield Static(id="tests-totals")
            with Horizontal(id="tests-body"):
                yield OptionList(*self._options(), id="tests-list")
                with VerticalScroll(id="tests-detail"):
                    yield Static(id="tests-case")
            yield Static(
                Text(
                    "↑/↓ case · p pass · f fail · s skip (again clears) · n note · "
                    "e export · Esc close",
                    style=theme.DIM,
                )
            )

    def on_mount(self) -> None:
        listing = self.query_one("#tests-list", OptionList)
        first = next((i for i, cid in enumerate(self._ids) if cid), 0)
        listing.highlighted = first
        listing.focus()
        self._refresh()

    def _options(self) -> List[Option]:
        options: List[Option] = []
        self._ids = []
        for flow in self._flows:
            options.append(
                Option(
                    Text(f"{flow.number} {flow.title}", style=f"bold {theme.CYAN}"), disabled=True
                )
            )
            self._ids.append("")
            for case in flow.cases:
                options.append(Option(self._case_line(case)))
                self._ids.append(case.id)
        return options

    def _case_line(self, case: Case) -> Text:
        mark = self._results.get(case.id, Result()).mark
        return Text.assemble(
            (f"{MARK_LABEL[mark]} ", MARK_STYLE[mark]),
            (f"{case.id} ", theme.TEXT),
            (case.title, theme.MUTED),
        )

    # --- the selected case ------------------------------------------------------------------
    def current_case(self) -> Optional[Case]:
        index = self.query_one("#tests-list", OptionList).highlighted
        if index is None or index >= len(self._ids) or not self._ids[index]:
            return None
        return test_guide.find_case(self._ids[index])

    def on_option_list_option_highlighted(self, _event: OptionList.OptionHighlighted) -> None:
        self._show_case()

    def _refresh(self) -> None:
        totals = test_guide.results.counts(self._flows, self._results)
        self.query_one("#tests-totals", Static).update(
            Text.assemble(
                ("PASS ", theme.DIM),
                (str(totals["PASS"]), MARK_STYLE["PASS"]),
                ("  FAIL ", theme.DIM),
                (str(totals["FAIL"]), MARK_STYLE["FAIL"]),
                ("  SKIP ", theme.DIM),
                (str(totals["SKIP"]), MARK_STYLE["SKIP"]),
                ("  not tested ", theme.DIM),
                (str(totals["TODO"]), theme.TEXT),
                ("   saved in ", theme.DIM),
                (str(test_guide.results.results_dir()), theme.MUTED),
            )
        )
        self._show_case()

    def _show_case(self) -> None:
        case = self.current_case()
        panel = self.query_one("#tests-case", Static)
        if case is None:
            panel.update(Text(""))
            return
        result = self._results.get(case.id, Result())
        text = Text()
        text.append(f"{case.id}  ", style=f"bold {theme.CYAN}")
        text.append(case.title, style=f"bold {theme.TEXT}")
        text.append("\n\n")
        if case.note:
            text.append(f"{case.note}\n\n", style=theme.MUTED)
        if case.ask:
            text.append("Type this\n", style=f"bold {theme.TEXT}")
            text.append(f"  {case.ask}\n\n", style=theme.TEAL)
        text.append("Steps\n", style=f"bold {theme.TEXT}")
        for number, step in enumerate(case.steps, 1):
            text.append(f"  {number}. ", style=theme.DIM)
            text.append(f"{step}\n", style=theme.MUTED)
        text.append("\nExpected\n", style=f"bold {theme.TEXT}")
        text.append(f"  {case.expect}\n\n", style=theme.MUTED)
        text.append("Result  ", style=f"bold {theme.TEXT}")
        text.append(result.mark or "not tested", style=MARK_STYLE[result.mark])
        if result.note:
            text.append(f"\nNote    {result.note}", style=theme.MUTED)
        panel.update(text)

    # --- actions ------------------------------------------------------------------------------
    def action_mark(self, mark: str) -> None:
        case = self.current_case()
        if case is None:
            return
        try:
            self._results[case.id] = test_guide.results.set_mark(case.id, mark)
        except (StoreValidationError, OSError) as exc:
            self.app.notify(str(exc), severity="warning", markup=False)
            return
        self._redraw_case(case)

    def _redraw_case(self, case: Case) -> None:
        listing = self.query_one("#tests-list", OptionList)
        index = self._ids.index(case.id)
        listing.replace_option_prompt_at_index(index, self._case_line(case))
        self._refresh()

    def action_note(self) -> None:
        case = self.current_case()
        if case is None:
            return
        current = self._results.get(case.id, Result()).note
        self.app.push_screen(
            TestNoteForm(case.id, current), lambda result: self._note_saved(case, result)
        )

    def _note_saved(self, case: Case, result: Optional[str]) -> None:
        if result == "saved":
            self._results = test_guide.results.load()
            self._redraw_case(case)

    def action_export(self) -> None:
        try:
            md_path, json_path = test_guide.results.export(self._flows)
        except OSError as exc:
            self.app.notify(f"Couldn't export: {exc}", severity="warning", markup=False)
            return
        self.app.notify(
            f"Saved {md_path} and {json_path.name}", title="Test results", markup=False, timeout=10
        )

    def action_close(self) -> None:
        self.dismiss(None)
