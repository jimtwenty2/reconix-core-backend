"""Drive the real TUI through the Start-screen input cases and save evidence.

    python scripts/capture_start_input_evidence.py

Each case starts a fresh app, presses real keys through Textual's Pilot, checks the result
and saves an SVG of the terminal to test-results/start-input/. A JSON summary (one row per
case: id, input, expected, actual, status, evidence) is written next to the screenshots for
docs/TEST_REPORT.md. The run plays instantly (RunController.SPEED = 0) so the gates arrive at
once; the menus keep their real ARM_DELAY. Saved assessments, reports and keys go to a temp
folder, never ~/.reconix. Exits 1 if any case fails.
"""

import asyncio
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Awaitable, Callable, List, Optional, Tuple

from textual import events

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reconix import store  # noqa: E402
from reconix.app import ReconixApp  # noqa: E402
from reconix.flow import RunController  # noqa: E402
from reconix.llm import config as llm_config  # noqa: E402
from reconix.screens import StartScreen, TemplateScreen  # noqa: E402
from reconix.store import persist, report  # noqa: E402
from reconix.widgets import PromptBox  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "test-results" / "start-input"
WIDE = (140, 45)
SMALL = (80, 24)


@dataclass
class Result:
    id: str
    scenario: str
    input: str
    expected: str
    actual: str
    status: str
    evidence: str


# A case presses keys on a running app and returns (passed, what actually happened).
Check = Callable[[ReconixApp, object], Awaitable[Tuple[bool, str]]]


def _box(app: ReconixApp) -> PromptBox:
    return app.screen.query_one(PromptBox)


def _decided() -> Tuple[bool, bool, int]:
    return (
        store.is_scope_approved(),
        store.get_run().plan_started,
        len(store.list_approval_decisions()),
    )


async def _settle(pilot, rounds: int = 6) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def _type(app: ReconixApp, pilot, text: str, enters: int = 1) -> None:
    """Type `text`; several Enters arrive as one burst, the way a terminal delivers them."""
    _box(app).input.value = text
    if enters == 1:
        await pilot.press("enter")
    else:
        for _ in range(enters):
            key = events.Key("enter", "\r")
            key.set_sender(app)
            app._driver.send_message(key)
    await _settle(pilot, rounds=10)


def _stays_on_start(app: ReconixApp, message_part: str) -> Tuple[bool, str]:
    message = _box(app).message if isinstance(app.screen, StartScreen) else ""
    ok = (
        isinstance(app.screen, StartScreen)
        and not store.get_run().started
        and message_part in message
    )
    return ok, (
        f"screen={type(app.screen).__name__}, run started={store.get_run().started}, "
        f"message={message!r}"
    )


def _rejects(text: str, message_part: str, enters: int = 1) -> Check:
    async def check(app: ReconixApp, pilot) -> Tuple[bool, str]:
        await _type(app, pilot, text, enters)
        return _stays_on_start(app, message_part)

    return check


async def _suggestions(app: ReconixApp, pilot) -> Tuple[bool, str]:
    await pilot.press("slash")
    await _settle(pilot)
    box = _box(app)
    ok = box.menu_open and box.menu.option_count > 10 and isinstance(app.screen, StartScreen)
    return ok, f"menu open={box.menu_open}, options={box.menu.option_count}"


async def _filter_and_tab(app: ReconixApp, pilot) -> Tuple[bool, str]:
    await pilot.press("slash", "f", "i", "n", "d", "down")
    await _settle(pilot)
    highlighted = _box(app).menu.highlighted_id
    await pilot.press("tab")
    await _settle(pilot)
    value = _box(app).input.value
    ok = highlighted == "finding" and value.startswith("/finding")
    return ok, f"options after '/find' + down: highlighted={highlighted!r}; after Tab: {value!r}"


async def _escape_sequence(app: ReconixApp, pilot) -> Tuple[bool, str]:
    await pilot.press("slash", "f")
    await _settle(pilot)
    await pilot.press("escape")
    first = (_box(app).menu_open, _box(app).input.value)
    await pilot.press("escape")
    second = _box(app).input.value
    await pilot.press("escape")
    await _settle(pilot)
    ok = first == (False, "/f") and second == "" and isinstance(app.screen, StartScreen)
    return ok, f"esc 1 -> menu open/text {first}; esc 2 -> text {second!r}; esc 3 -> still Start"


async def _valid_target(app: ReconixApp, pilot) -> Tuple[bool, str]:
    await _type(app, pilot, "https://app.example.com", enters=3)
    ok = (
        isinstance(app.screen, TemplateScreen)
        and store.waiting_gate() == "scope"
        and _decided() == (False, False, 0)
        and len(store.list_requests()) == 1
    )
    return ok, (
        f"screen={type(app.screen).__name__}, gate={store.waiting_gate()!r}, "
        f"scope approved/plan run/approvals={_decided()}, "
        f"requests={len(store.list_requests())}"
    )


async def _layout(app: ReconixApp, pilot) -> Tuple[bool, str]:
    await pilot.press("slash")
    await _settle(pilot)
    width, height = app.size
    box = _box(app)
    regions = {
        "logo": app.screen.query_one("#logo").region,
        "input": box.input.region,
        "suggestions": box.menu.region,
        "rail": app.screen.query_one("FlowProgress").region,
    }
    inside = all(
        r.height > 0 and r.y >= 0 and r.bottom <= height and r.right <= width
        for r in regions.values()
    )
    return inside, f"{width}x{height}: " + ", ".join(f"{k}={tuple(v)}" for k, v in regions.items())


CASES: List[Tuple[str, str, str, str, Check, Tuple[int, int], Optional[str]]] = [
    # (id, scenario, input, expected, check, size, screenshot name)
    (
        "TUI-01",
        "Empty input",
        "(Enter on an empty prompt)",
        "Nothing starts; hint shown",
        _rejects("", "Type a target"),
        WIDE,
        "01-empty-input",
    ),
    (
        "TUI-02",
        "Whitespace-only input",
        "'   \\t  '",
        "Nothing starts; hint shown",
        _rejects("   \t  ", "Type a target"),
        WIDE,
        None,
    ),
    (
        "TUI-03",
        "Unknown command",
        "/plna",
        "Error with 'Did you mean /plan?'",
        _rejects("/plna", "Did you mean /plan?"),
        WIDE,
        "02-unknown-command",
    ),
    (
        "TUI-04",
        "Known command, bad argument",
        "/plan now",
        "Usage line",
        _rejects("/plan now", "Usage: /plan"),
        WIDE,
        None,
    ),
    (
        "TUI-05",
        "Suggestions on '/'",
        "/",
        "Suggestion list opens",
        _suggestions,
        WIDE,
        "03-suggestions",
    ),
    (
        "TUI-06",
        "Filter, ArrowDown, Tab",
        "/find, Down, Tab",
        "Highlight moves; Tab completes /finding",
        _filter_and_tab,
        WIDE,
        None,
    ),
    (
        "TUI-07",
        "Escape order",
        "/f, Esc x3",
        "Close list, clear, then nothing",
        _escape_sequence,
        WIDE,
        None,
    ),
    (
        "TUI-08",
        "Invalid IPv4",
        "256.0.0.1",
        "Error; nothing starts",
        _rejects("256.0.0.1", "isn't a valid IPv4 address"),
        WIDE,
        "04-invalid-target",
    ),
    (
        "TUI-09",
        "Unsupported URL scheme",
        "file:///etc/passwd",
        "Error; nothing starts",
        _rejects("file:///etc/passwd", "file: links aren't supported"),
        WIDE,
        None,
    ),
    (
        "TUI-10",
        "Dash range",
        "10.0.0.1-20",
        "Asks for CIDR; nothing starts",
        _rejects("10.0.0.1-20", "use CIDR"),
        WIDE,
        None,
    ),
    (
        "TUI-11",
        "Very long input",
        "'a' x 600",
        "Length error; nothing starts",
        _rejects("a" * 600, "keep it under"),
        WIDE,
        None,
    ),
    (
        "TUI-12",
        "Shell metacharacters",
        "; rm -rf /",
        "Treated as chat; nothing runs or starts",
        _rejects("; rm -rf /", ""),
        WIDE,
        None,
    ),
    (
        "TUI-13",
        "Valid target, Enter x3",
        "https://app.example.com",
        "Stops at the scope gate; nothing approved",
        _valid_target,
        WIDE,
        "05-valid-target-gate",
    ),
    (
        "TUI-14",
        "Layout at 80x24",
        "/",
        "Logo, rail, input and list on screen",
        _layout,
        SMALL,
        "06-layout-80x24",
    ),
    (
        "TUI-15",
        "Layout at 160x50",
        "/",
        "Logo, rail, input and list on screen",
        _layout,
        (160, 50),
        None,
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
    case_id, scenario, shown, expected, check, size, shot = case
    store.reset()
    app = ReconixApp()
    async with app.run_test(size=size) as pilot:
        await _settle(pilot)
        try:
            ok, actual = await check(app, pilot)
        except Exception as exc:  # a crash is a failed case, recorded, not a lost run
            ok, actual = False, f"crashed: {exc!r}"
        name = f"{shot or case_id.lower()}.svg"
        app.save_screenshot(filename=name, path=str(OUT))
    evidence = f"apps/tui/test-results/start-input/{name}"
    return Result(case_id, scenario, shown, expected, actual, "PASS" if ok else "FAIL", evidence)


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
