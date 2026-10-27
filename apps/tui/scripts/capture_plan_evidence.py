"""Drive the real TUI to the Plan screen in each state and save evidence.

    python scripts/capture_plan_evidence.py

Each case starts a fresh app on the demo data, sets the run up through the store (as the
run itself would), opens the Plan screen, presses real keys through Textual's Pilot,
checks the result and saves an SVG of the terminal to test-results/plan/. A JSON summary
(id, scenario, expected, actual, status, evidence) is written next to the screenshots for
docs/TEST_REPORT.md. Steps play instantly (RunController.SPEED = 0). Saved assessments,
reports and keys go to a temp folder, never ~/.reconix. Exits 1 if any case fails.
"""

import asyncio
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Awaitable, Callable, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from textual.widgets import OptionList  # noqa: E402

from reconix import store  # noqa: E402
from reconix.app import ReconixApp  # noqa: E402
from reconix.flow import RunController  # noqa: E402
from reconix.llm import config as llm_config  # noqa: E402
from reconix.screens import PlanScreen  # noqa: E402
from reconix.store import persist, report  # noqa: E402
from tests.support import decide, play_until_gate, run_to  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "test-results" / "plan"
WIDE = (140, 45)
SMALL = (80, 24)


@dataclass
class Result:
    id: str
    scenario: str
    expected: str
    actual: str
    status: str
    evidence: str


Check = Callable[[ReconixApp, object], Awaitable[Tuple[bool, str]]]


def _to_busy() -> None:
    run_to("scope")
    decide("scope")


def _to_running() -> None:
    run_to("plan")
    decide("plan")
    play_until_gate()


def _to_stopped_mid_plan() -> None:
    _to_running()
    store.stop_run()


def _question(app: ReconixApp) -> str:
    return " ".join(str(w.render()) for w in app.screen.query(".question"))


def _choices(app: ReconixApp) -> List[str]:
    menus = app.screen.query("#plan-menu")
    return [c.id for c in menus.first()._choices] if menus else []


def _expects(state: str, question: str, choices: List[str]) -> Check:
    async def check(app: ReconixApp, pilot) -> Tuple[bool, str]:
        shown = (PlanScreen.state(), _question(app), _choices(app))
        ok = shown[0] == state and question in shown[1] and shown[2] == choices
        return ok, f"state={shown[0]}, question={shown[1]!r}, choices={shown[2]}"

    return check


async def _busy(app: ReconixApp, pilot) -> Tuple[bool, str]:
    menu = bool(app.screen.query("#plan-menu"))
    spinner = bool(app.screen.query(".spinner"))
    ok = PlanScreen.state() == "busy" and not menu and spinner
    return ok, f"state={PlanScreen.state()}, menu shown={menu}, spinner={spinner}"


async def _edit_disabled(app: ReconixApp, pilot) -> Tuple[bool, str]:
    edit = next(c for c in app.screen.query_one("#plan-menu")._choices if c.id == "edit")
    note = app.screen.query("#plan-edit-note")
    await pilot.press("2")
    for _ in range(4):
        await pilot.pause()
    stayed = isinstance(app.screen, PlanScreen)
    ok = edit.disabled and bool(note) and stayed
    return ok, f"edit disabled={edit.disabled}, reason shown={bool(note)}, '2' ignored={stayed}"


async def _full_command(app: ReconixApp, pilot) -> Tuple[bool, str]:
    rows = store.plan_overview()
    index = next(i for i, row in enumerate(rows) if row.command)
    await pilot.press("tab", *["down"] * index)
    for _ in range(4):
        await pilot.pause()
    plan_list = app.screen.query_one("#plan-list", OptionList)
    shown = str(plan_list.get_option_at_index(index).prompt)
    ok = app.focused is plan_list and f"$ {rows[index].command}" in shown
    return ok, f"step list focused={app.focused is plan_list}, row {rows[index].num} in full={ok}"


async def _layout(app: ReconixApp, pilot) -> Tuple[bool, str]:
    width, _ = app.size
    plan_list = app.screen.query_one("#plan-list", OptionList)
    body = app.screen.query_one("#body")
    inner = plan_list.scrollable_content_region.width
    lines_fit = all(
        len(line) <= inner
        for i in range(plan_list.option_count)
        if i != plan_list.highlighted
        for line in str(plan_list.get_option_at_index(i).prompt).split("\n")
    )
    ok = (
        plan_list.region.right <= width
        and plan_list.max_scroll_x == 0
        and body.max_scroll_x == 0
        and lines_fit
    )
    return ok, (
        f"{width}: list right edge={plan_list.region.right}, horizontal scroll="
        f"{plan_list.max_scroll_x + body.max_scroll_x}, rows fit={lines_fit}"
    )


# (id, scenario, expected, set-up, check, size, screenshot name, patch can_edit off)
CASES = [
    (
        "PLAN-01",
        "None",
        "Empty state; only 'Pick a template'",
        lambda: store.start_run("Assess staging.example.com"),
        _expects("none", "Go to the template?", ["template"]),
        WIDE,
        None,
        False,
    ),
    (
        "PLAN-02",
        "Draft",
        "Rows; 'Approve the scope first'",
        lambda: run_to("scope"),
        _expects("draft", "Approve the scope first", ["template", "chat"]),
        WIDE,
        None,
        False,
    ),
    ("PLAN-03", "Busy", "Rows and spinner; no action", _to_busy, _busy, WIDE, None, False),
    (
        "PLAN-04",
        "Ready",
        "Run plan / Edit steps / Cancel",
        lambda: run_to("plan"),
        _expects("ready", "Run this plan?", ["run", "edit", "cancel", "type", "chat"]),
        WIDE,
        "plan-ready",
        False,
    ),
    (
        "PLAN-05",
        "Running",
        "Live rows; only 'View execution'",
        _to_running,
        _expects("running", "The plan is running.", ["execution", "chat"]),
        WIDE,
        "plan-running",
        False,
    ),
    (
        "PLAN-06",
        "Finished",
        "Finished panel; findings and execution",
        lambda: run_to(None),
        _expects("finished", "The plan has run.", ["findings", "execution", "chat"]),
        WIDE,
        "plan-finished",
        False,
    ),
    (
        "PLAN-07",
        "Stopped while the plan ran",
        "Stopped, not 'has run'; results kept",
        _to_stopped_mid_plan,
        _expects("stopped", "What ran is kept.", ["findings", "execution", "new"]),
        WIDE,
        "plan-stopped-mid-plan",
        False,
    ),
    (
        "PLAN-08",
        "Edit steps disabled",
        "Disabled, reason shown, '2' ignored",
        lambda: run_to("plan"),
        _edit_disabled,
        WIDE,
        "plan-edit-disabled",
        True,
    ),
    (
        "PLAN-09",
        "Highlighted row in full",
        "Tab to steps; long command shown whole",
        lambda: run_to("plan"),
        _full_command,
        SMALL,
        None,
        False,
    ),
    (
        "PLAN-10",
        "Layout 80x24",
        "No horizontal overflow; rows fit",
        lambda: run_to("plan"),
        _layout,
        SMALL,
        "plan-layout-80x24",
        False,
    ),
    (
        "PLAN-11",
        "Layout 160x50",
        "No horizontal overflow; rows fit",
        lambda: run_to("plan"),
        _layout,
        (160, 50),
        None,
        False,
    ),
]


def _isolate(tmp: Path) -> None:
    """Keep everything the app saves inside `tmp` (as the test suite does)."""
    RunController.SPEED = 0
    report.REPORTS_DIR = tmp / "reports"
    persist.DATA_DIR = tmp / "assessments"
    persist.WEB_URL_FILE = tmp / "web.url"
    llm_config.DB_PATH = tmp / "llm.db"
    llm_config.KEY_FILE = tmp / "llm.key"


async def _run(case) -> Result:
    case_id, scenario, expected, setup, check, size, shot, nothing_editable = case
    store.reset()
    setup()
    can_edit = store.can_edit
    if nothing_editable:
        store.can_edit = lambda request_id: False  # every demo step is editable
    app = ReconixApp()
    try:
        async with app.run_test(size=size) as pilot:
            app.goto("plan")
            for _ in range(6):
                await pilot.pause()
            try:
                ok, actual = await check(app, pilot)
            except Exception as exc:  # a crash is a failed case, recorded
                ok, actual = False, f"crashed: {exc!r}"
            name: Optional[str] = f"{shot or case_id.lower()}.svg"
            app.save_screenshot(filename=name, path=str(OUT))
    finally:
        store.can_edit = can_edit
    return Result(
        case_id,
        scenario,
        expected,
        actual,
        "PASS" if ok else "FAIL",
        f"apps/tui/test-results/plan/{name}",
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        _isolate(Path(tmp))
        results = [asyncio.run(_run(case)) for case in CASES]
    (OUT / "results.json").write_text(
        json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    for r in results:
        print(f"{r.status:4}  {r.id}  {r.scenario}: {r.actual}")
    failed = [r for r in results if r.status != "PASS"]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed -> {OUT}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
