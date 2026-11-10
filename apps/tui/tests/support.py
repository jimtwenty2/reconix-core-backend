"""Helpers shared by the tests: driving the store's run, and driving the UI."""

import importlib.util
import io
import time
from typing import Callable, List, Optional

import pytest

from reconix import store

SIZE = (140, 45)  # fixed terminal size so layout-dependent widgets behave the same

TEST_PASSWORD = "s3cret-Pa55-for-tests"  # must never appear anywhere it is shown or saved

# A bare hostname could be a site, an API or a network host, so the run asks for the
# template. The demo request (a URL) and IPv4/repo/path targets pick theirs themselves.
ASK_REQUEST = "Assess staging.example.com"
# A request the tests start runs with (reserved names only; the fake API answers it).
DEMO_REQUEST = "Assess https://staging.example.com for web security issues."

NETWORK = "10.0.0.0/24"  # a network scope: the scope's tick list shows ports and tools

# Agent mode drives the backend `harness` package. It lives with the backend, not in apps/,
# so the tests that need it skip when it isn't installed (the scripted demo needs no harness).
needs_harness = pytest.mark.skipif(
    importlib.util.find_spec("harness") is None, reason="needs the backend harness package"
)


def event_kinds() -> List[str]:
    return [event.kind for event in store.list_events()]


# --- the run, straight through the store ---------------------------------------------------
def drive_live() -> bool:
    """Make the run's next Core API call (the fake API in tests) the way the app's worker
    does, but inline. False when there is nothing to ask."""
    job = store.next_live_job()
    if job is None:
        return False
    try:
        result = job.fetch()
    except Exception as exc:  # noqa: BLE001 - recorded like the app records it
        job.fail(exc)
    else:
        job.apply(result)
    return True


def draft_plan() -> None:
    """Draft the plan on the (fake) Core API, as the app does after the scope is approved."""
    request = store.plan_draft_request()
    if request is None:
        return
    try:
        out = store.fetch_plan_draft(request)
    except Exception as exc:  # noqa: BLE001
        store.plan_draft_failed(request, str(exc))
    else:
        store.apply_plan_draft(request, out)


def play_until_gate() -> Optional[str]:
    """Advance the store's run until it waits at a gate (returns it) or ends (None). When
    the script runs out, the run's next Core API call is made, as the app makes it."""
    while True:
        step = store.advance()
        if step is None:
            if drive_live():
                continue
            return None
        if step.kind == "gate" and store.waiting_gate() == step.name:
            return step.name


def auth_values(challenge) -> dict:
    """Fill a login step: a test account or a cookie, or (the code step) a dummy OTP code."""
    out = {}
    for field in challenge.fields:
        out[field.id] = "123456" if field.otp else TEST_PASSWORD if field.secret else "demo.tester"
    return out


def decide(gate: str) -> None:
    """Make the human decision a gate waits for, straight through the store."""
    if gate == "template":
        store.select_template(store.get_assessment().template_id)
    elif gate == "scope":
        store.approve_scope()
        draft_plan()
    elif gate == "plan":
        store.run_plan()
    elif gate in ("account", "code"):
        store.provide_auth(auth_values(store.current_auth_challenge()))
    elif gate.startswith("approval:"):
        request = store.get_approval(gate.split(":", 1)[1])
        if request.risk == "HIGH":
            token = store.request_confirmation(request.request_id, request.command_hash)
            store.approve(
                request.request_id,
                command_hash=request.command_hash,
                confirmation_token=token,
                typed_target=request.target,
            )
        else:
            store.approve(request.request_id, command_hash=request.command_hash)
    else:
        raise ValueError(gate)


def run_to(target: Optional[str], request: str = DEMO_REQUEST) -> None:
    """Start a run and decide every gate until `target` is waiting (None: to the end).

    The demo request skips the template gate (its URL picks Web URL); pass
    `ASK_REQUEST` to stop at "template".
    """
    store.start_run(request)
    while True:
        gate = play_until_gate()
        if gate is None or gate == target:
            return
        decide(gate)


def run_to_end() -> None:
    """Decide every gate of a run that has already started, until it ends."""
    while True:
        gate = play_until_gate()
        if gate is None:
            return
        decide(gate)


# --- driving the UI ------------------------------------------------------------------------
def screen_text(screen) -> str:
    """Everything a screen or dialog shows in its Static widgets, as plain text."""
    from rich.console import Console
    from textual.widgets import Static

    out = []
    for static in screen.query(Static):
        console = Console(file=io.StringIO(), width=120, force_terminal=False)
        console.print(static.content)
        out.append(console.file.getvalue())
    return "\n".join(out)


async def settle(pilot, rounds: int = 4) -> None:
    """Let screen switches, dialogs (pushed on the app's next turn) and redraws land."""
    for _ in range(rounds):
        await pilot.pause()


async def wait_until(
    pilot, cond: Callable[[], bool], timeout: float = 5.0, what: str = "condition"
) -> None:
    """Pause the app until `cond()` holds (a worker finished, a gate opened, a line showed up),
    or fail after `timeout` seconds. Replaces fixed `settle(rounds=N)` waits on background work."""
    deadline = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout}s waiting for {what}")
        await pilot.pause(0.05)


async def show(app, pilot, name: str) -> None:
    """Jump straight to a flow screen and let it mount."""
    app.goto(name)
    await settle(pilot)


async def choose_by_keys(pilot, choice_id: str) -> None:
    """Pick `choice_id` in the focused menu the way a person must pick a destructive choice
    (no digit reaches it): move the highlight with ↓ / ↑, then press Enter."""
    from reconix.widgets import ChoiceMenu

    menu = pilot.app.screen.focused
    assert isinstance(menu, ChoiceMenu), f"no menu has focus: {menu!r}"
    ids = [choice.id for choice in menu._choices]
    target = ids.index(choice_id)
    while menu.highlighted != target:
        await pilot.press("down" if menu.highlighted < target else "up")
    await pilot.press("enter")
    await settle(pilot)


async def start_demo(pilot) -> None:
    """Type the demo request at the Start prompt; the run stops at the scope."""
    await type_request(pilot, DEMO_REQUEST)


async def type_request(pilot, text: str) -> None:
    """Type `text` into the prompt on screen and submit it with Enter."""
    from reconix.widgets import PromptBox

    box = pilot.app.screen.query_one(PromptBox)
    box.input.value = text
    box.input.focus()
    await pilot.press("enter")
    await settle(pilot)


async def pass_gate(app, pilot) -> str:
    """Make the decision the run waits for, with the keyboard. Returns the gate."""
    from textual.widgets import Input

    from reconix.screens import ApprovalScreen, ChoiceScreen, PlanScreen, TemplateScreen
    from reconix.screens.forms import LoginForm, OpenApiForm

    gate = store.waiting_gate()
    screen = app.screen
    if isinstance(screen, OpenApiForm):
        # The API template auto-opens its base URL and spec form at the scope gate (two fields,
        # the base URL prefilled); skip it (Cancel) and decide the scope on the review screen
        # underneath.
        await pilot.press("escape")
        await settle(pilot)
        screen = app.screen
    if isinstance(screen, TemplateScreen):
        await pilot.press("1" if gate == "scope" else "enter")  # Approve / the suggestion
    elif isinstance(screen, PlanScreen):
        await pilot.press("1")  # Run plan
    elif isinstance(screen, LoginForm):
        for field_id, value in auth_values(store.current_auth_challenge()).items():
            screen.query_one(f"#{field_id}", Input).value = value
        screen.query_one("#submit").press()
    elif isinstance(screen, ApprovalScreen):
        request = store.get_approval(gate.split(":", 1)[1])
        if request.risk == "HIGH":
            from reconix.screens.forms.typed_target import TypedTargetForm

            await pilot.press("1")  # Approve & run
            await settle(pilot)
            assert isinstance(app.screen, ChoiceScreen)
            await pilot.press("down", "enter")  # Yes (No is the default)
            await settle(pilot)
            assert isinstance(app.screen, TypedTargetForm)
            app.screen.query_one("#target", Input).value = request.target
            app.screen.query_one("#submit").press()
        else:
            await pilot.press("1")
    else:
        raise AssertionError(f"no gate is open (screen: {screen!r}, gate: {gate!r})")
    await settle(pilot)
    return gate


async def run_ui_to(app, pilot, target: Optional[str], request: Optional[str] = None) -> None:
    """Start a run and pass gates with the keyboard until `target` is waiting.

    No `request`: the demo request is typed. Otherwise `request` is typed into the Start
    prompt and submitted.
    """
    if request is None:
        await start_demo(pilot)
    else:
        await type_request(pilot, request)
    tries: dict = {}
    while True:
        await wait_for_run(pilot)
        gate = store.waiting_gate()
        if not gate or gate == target or store.is_finished():
            break
        tries[gate] = tries.get(gate, 0) + 1
        if tries[gate] > 3:  # the API keeps refusing it (e.g. a source scope): stop, don't loop
            raise AssertionError(f"the run stays at {gate!r}: {toasts(app)[-1:]}")
        await pass_gate(app, pilot)
    assert store.waiting_gate() == (target or "") or (target is None and store.is_finished())


async def wait_for_run(pilot, timeout: float = 10.0) -> None:
    """Let the app's Core API workers finish: the plan draft, or the run's next call, until
    the run waits at a gate, ends, or stopped on a failed call."""

    def settled() -> bool:
        run = store.get_assessment()
        busy = run.live.busy or run.plan_drafting
        return not busy and (
            bool(store.waiting_gate()) or store.is_finished() or bool(store.live_failed())
        )

    await wait_until(pilot, settled, timeout)


# --- a finding that did not come from the scripted run ---------------------------------------
def add_finding(
    title: str,
    path: str = "/x",
    *,
    severity: str = "LOW",
    description: str = "",
    evidence: Optional[List[str]] = None,
    evidence_summary: str = "",
    validation: str = "UNCONFIRMED",
    validation_reason: str = "",
    validation_method: str = "",
) -> None:
    """Add one revealed finding the way the AI agent does (`AI-NNN`), for tests that need
    odd text in a finding (control bytes, secrets) without a scripted template."""
    from reconix.models import Finding
    from reconix.store.findings import ingest_external

    ingest_external(
        [
            Finding(
                fid="",
                severity=severity,
                title=title,
                path=path,
                validation=validation,
                confidence="TENTATIVE",
                description=description,
                affected_url=path,
                impact="",
                remediation="",
                tool="agent",
                evidence=list(evidence or []),
                evidence_summary=evidence_summary,
                validation_reason=validation_reason,
                validation_method=validation_method,
                category="Web App",
            )
        ]
    )


# --- the step chat (screens/base.py, widgets/step_chat.py) ---------------------------------------
def toasts(app) -> List[str]:
    """The notifications shown so far, as text."""
    return [str(n.message) for n in app._notifications]


def fake_model(monkeypatch) -> list:
    """Chat calls answer "model answer N"; returns the list of messages each call got."""
    from reconix.llm import client

    calls: list = []

    def complete(pid, model, messages, **kw):
        calls.append(messages)
        return f"model answer {len(calls)}"

    monkeypatch.setattr(client, "complete", complete)
    return calls


def step_menu(app):
    """The step's own menu (the first ChoiceMenu on the screen)."""
    from reconix.widgets import ChoiceMenu

    return app.screen.query(ChoiceMenu).first()


def type_in_menu(app, text: str) -> None:
    """A line typed on the step menu's "Type something." row."""
    from reconix.widgets import ChoiceMenu

    app.screen.post_message(ChoiceMenu.Typed(step_menu(app), text))


def chat_about_this(app) -> None:
    """Choose "Chat about this" on the step's menu."""
    from reconix.widgets import ChoiceMenu

    app.screen.post_message(ChoiceMenu.Chosen(step_menu(app), "chat"))


def chat_text(app) -> str:
    """Everything the step chat shows ("" when no chat is open)."""
    from reconix.widgets import StepChat

    chats = app.screen.query(StepChat)
    return screen_text(chats.first()) if chats else ""


async def ask_in_chat(app, pilot, text: str) -> None:
    """Type `text` into the step chat's input and press Enter."""
    from reconix.widgets import StepChat

    chat = app.screen.query_one(StepChat)
    chat.input.value = text
    chat.input.focus()
    await pilot.press("enter")
    await settle(pilot)


def chat_menu(app):
    """The newest menu inside the chat (an older one may still be leaving), or None."""
    menus = [q.menu for q in app.screen.query(".chat-decision") if q.is_mounted]
    return menus[-1] if menus else None


async def chat_menu_ready(app, pilot):
    """The menu inside the chat, focused and past its arm delay (a key now counts)."""
    await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
    menu = chat_menu(app)
    await wait_until(pilot, lambda: menu.has_focus, what="the menu focused")
    await pilot.pause(menu.ARM_DELAY + 0.1)
    return menu
