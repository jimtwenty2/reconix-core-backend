"""Frame 04 — Human approval gate (MEDIUM: one decision; HIGH: a double check).

The run stops here when it reaches a gated action. The store is the authority: it re-checks
the command hash and, for HIGH risk, the single-use confirmation token; the screen only asks.
When nothing is waiting, the screen lists the decisions made and the actions still ahead.
"""

import asyncio
from copy import deepcopy
from typing import List, Optional

from rich.console import RenderableType
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widget import Widget
from textual.widgets import Static

from .base import ReconixScreen
from .choice import ChoiceScreen, details_body
from .. import store, theme
from ..models import GATE_APPROVAL_PREFIX, ApprovalRequest, Choice
from ..store.redact import redact
from ..widgets import ChoiceMenu, Question, menu_hint

MASKED_NOTE = "secrets masked on screen"


def waiting_request() -> Optional[ApprovalRequest]:
    """The approval request the run is waiting on right now, if any."""
    gate = store.waiting_gate()
    if not gate.startswith(GATE_APPROVAL_PREFIX) or store.gate_state(gate) != "pending":
        return None
    return store.get_approval(gate[len(GATE_APPROVAL_PREFIX):])


def _row(label: str, *parts) -> Static:
    return Static(Text.assemble((f"{label:<12}", theme.DIM), *parts), classes="approval-row")


class ApprovalScreen(ReconixScreen):
    flow_name = "approval"
    mode_name = "APPROVAL"

    BINDINGS = [
        Binding("enter", "choose", "select", show=False),
        Binding("d", "details", "details"),
        Binding("escape", "later", "decide later"),
    ]

    def __init__(self) -> None:
        super().__init__()
        request = waiting_request()
        # A copy: what the operator approves is what was shown (the store re-checks the hash).
        self._request: Optional[ApprovalRequest] = deepcopy(request) if request else None
        self._masked = False   # display-only masking happened in the part being built
        self._fit_level = 0    # 0 = full layout; higher = more compact (see `_waiting_widgets`)

    def _mask(self, text: str) -> str:
        """Mask secrets for display only, and note that it happened. The real command, its
        hash and `store.approve()` are untouched; nothing masked is hashed, stored or logged."""
        masked = redact(text)
        if masked != text:
            self._masked = True
        return masked

    def view_state(self) -> object:
        request = waiting_request()       # an edit changes the hash: rebuild with the new one
        return (request.request_id, request.command_hash) if request else ""

    @property
    def _high(self) -> bool:
        return self._request is not None and self._request.risk == "HIGH"

    # --- layout ------------------------------------------------------------------------------
    def compose_body(self) -> ComposeResult:
        self._masked = False
        if self._request is None:
            yield from self._compose_idle()
        else:
            yield from self._waiting_widgets(self._request)

    def _waiting_widgets(self, req: ApprovalRequest) -> List[Widget]:
        """The gated-action panel and its menu, built for the current fit level.

        Level 0 is today's full layout (kept at 120x36). Higher levels drop optional parts one
        at a time so that at 80x24 the risk, Action, Target, the full "$ command", the hash and
        every menu label stay on screen at once (see `_fit`). Masking is display-only.
        """
        self._masked = False
        level = self._fit_level
        compact = level >= 1
        approvals = [a.request_id for a in store.get_assessment().approvals]
        position = approvals.index(req.request_id) + 1 if req.request_id in approvals else 1

        # Always shown: risk (panel subtitle), Action, Target, the full command and the hash.
        rows: List[Widget] = [
            _row("Action", (self._mask(req.action), f"bold {theme.TEXT}")),
            _row("Target", (self._mask(req.target), f"bold {theme.TEAL}"),
                 ("   ✓ policy check passed", theme.GREEN)),
        ]
        if level < 3:                                   # Purpose/Impact (merged once compact)
            if compact:
                rows.append(_row("Purpose", (self._mask(req.purpose), theme.MUTED),
                                 ("  ·  ", theme.DIM), (self._mask(req.impact), theme.MUTED)))
            else:
                rows.append(_row("Purpose", (self._mask(req.purpose), theme.MUTED)))
                rows.append(_row("Impact", (self._mask(req.impact), theme.MUTED)))
        if not compact:                                 # spacer + label only in the full layout
            rows.append(Static(""))
            rows.append(Static(Text("EXACT REQUEST", style=theme.DIM)))
        rows.append(Static(Text.assemble(
            ("$ ", f"bold {theme.GREEN}"), (self._mask(req.command), theme.TEXT),
            ("   ", ""), (req.command_hash[:23] + "…", theme.DIM)), classes="panel-note"))

        risk_color = theme.RISK.get(req.risk, theme.MUTED)
        panel = Vertical(*rows, classes="panel danger" if self._high else "panel accent")
        panel.border_title = "◆ HUMAN APPROVAL REQUIRED"
        panel.border_subtitle = f"[{risk_color}]◆ {req.risk} RISK[/]"

        if compact:                                     # one line per choice; keep the two warnings
            choices = [
                Choice("approve", "Approve & run", "double-check first" if self._high else ""),
                Choice("reject", "Reject", "stops the run, nothing else runs", "danger"),
                Choice("details", "View details"),
                Choice("edit", "Edit params", disabled=not req.param_label),
            ]
            question = Question("Approval", "", choices, default=2,
                                hint=menu_hint("decide later"), menu_id="approval-menu",
                                typing=False, chat=False, inline=True, show_hint=level < 2)
        else:
            choices = [
                Choice("approve", "Approve & run",
                       "HIGH risk: you double-check the exact request first." if self._high
                       else "Runs this one request now."),
                Choice("reject", "Reject",
                       "Not executed. The assessment stops; nothing else runs.", "danger"),
                Choice("details", "View details", "Scope limits, exact request and audit trail."),
                self._edit_choice(req),
            ]
            question = Question(
                "Approval", f"Run {self._mask(req.action)} on "
                f"{self._mask(store.get_assessment().target)}?",
                choices, default=2, hint=menu_hint("decide later"), menu_id="approval-menu")

        context = next((e.message for e in reversed(store.list_activity())
                        if e.source == "AI"), "testing in progress")
        widgets: List[Widget] = []
        if level < 1:                                   # the "✓ context" line
            widgets.append(Static(Text.assemble(("✓ ", theme.GREEN),
                                                 (self._mask(context), theme.DIM))))
        if level < 4:                                   # the "gated action N of M" line
            widgets.append(Static(Text.assemble(("◆ reconix ", theme.CYAN), (
                f"gated action {position} of {len(approvals)} requires your approval",
                theme.DIM)), classes="ai-label"))
        widgets.append(panel)
        if self._masked:                                # shown whenever a secret was masked
            widgets.append(Static(Text(MASKED_NOTE, style=theme.DIM)))
        widgets.append(question)
        if level < 1:                                   # the "logged to audit" line
            widgets.append(Static(Text(f"logged to audit · operator: {store.current_operator()}",
                                       style=theme.DIM)))
        return widgets

    @staticmethod
    def _edit_choice(req: ApprovalRequest) -> Choice:
        if not req.param_label:
            return Choice("edit", "Edit params", disabled=True)
        return Choice("edit", "Edit params",
                      f"Change the {req.param_label.lower()} first; the policy checks it again.")

    def _compose_idle(self) -> ComposeResult:
        yield Static(Text.assemble(("◆ reconix ", theme.CYAN), (
            "no action is waiting for your approval", theme.DIM)), classes="ai-label")
        with Vertical(classes="panel") as panel:
            panel.border_title = "◆ GATED ACTIONS"
            panel.border_subtitle = "the run pauses at each one"
            approvals = store.get_assessment().approvals
            if not approvals:
                yield Static(Text("None yet — they come from the template's plan.",
                                  style=theme.MUTED))
            for request in approvals:
                yield Static(self._decision_line(request))
            if self._masked:
                yield Static(Text(MASKED_NOTE, style=theme.DIM))
        if store.is_plan_started():
            choices = [Choice("execution", "Back to execution", recommended=True)]
        else:
            choices = [Choice("plan", "Review the plan", recommended=True)]
        yield Question("Approval", "Nothing to decide right now.", choices,
                       hint=menu_hint("go back"), typing=False, chat=False,
                       menu_id="approval-menu")

    def _decision_line(self, request: ApprovalRequest) -> Text:
        decision = store.decision_for(request.request_id)
        line = Text.assemble(
            (f"● {request.risk:<7}", f"bold {theme.RISK.get(request.risk, theme.MUTED)}"),
            (f"{self._mask(request.action):<32}", theme.TEXT))
        if decision is None:
            line.append("· pending", style=theme.DIM)
        else:
            approved = decision.decision == "APPROVED"
            line.append("✓ approved" if approved else "✕ rejected",
                        style=theme.GREEN if approved else theme.CRITICAL)
            line.append(f" by {decision.operator} at {decision.created_at:%H:%M:%S}",
                        style=theme.DIM)
            if decision.reason:
                line.append(f" · “{self._mask(decision.reason)}”", style=theme.MUTED)
        return line

    # --- responsive fit: compact the panel only when the full layout doesn't fit -------------
    MAX_FIT_LEVEL = 4

    def on_mount(self) -> None:
        self.focus_menu("approval-menu")
        if self._request is not None:
            self.run_worker(self._fit(rebuild=False), exclusive=True, group="approval-fit")

    def on_resize(self, event: events.Resize) -> None:
        if self._request is not None:
            self._fit_level = 0                 # start from the full layout, then shrink to fit
            self.run_worker(self._fit(rebuild=True), exclusive=True, group="approval-fit")

    async def _fit(self, *, rebuild: bool) -> None:
        """Drop one optional part at a time until the panel and its menu stop overflowing.

        Measured, not hard-coded: 120x36 fits at level 0 so it keeps the full layout; 80x24
        escalates. The risk, Action, Target, command, hash and menu labels are never dropped."""
        if rebuild:
            await self._relayout()
        while True:
            await self._after_refresh()
            if self._request is None or not self.is_mounted:
                return
            body = self.query_one("#body")
            if body.max_scroll_y == 0 or self._fit_level >= self.MAX_FIT_LEVEL:
                return
            self._fit_level += 1
            await self._relayout()

    async def _relayout(self) -> None:
        if self._request is None or not self.is_mounted:
            return
        body = self.query_one("#body")
        await body.remove_children()
        await body.mount(*self._waiting_widgets(self._request))
        if self.app.screen is self:             # never steal focus from a dialog on top
            self.focus_menu("approval-menu")

    async def _after_refresh(self) -> None:
        """Wait one refresh so the new layout's scroll height is up to date before measuring."""
        fut = asyncio.get_running_loop().create_future()
        self.call_after_refresh(lambda: fut.done() or fut.set_result(None))
        await fut

    # --- choices -----------------------------------------------------------------------------
    def on_choice_menu_chosen(self, event: ChoiceMenu.Chosen) -> None:
        event.stop()
        handlers = {"approve": self.action_approve, "reject": self.action_reject,
                    "details": self.action_details, "edit": self.action_edit,
                    "chat": self.chat_about,
                    "execution": lambda: self.app.goto("execution"),
                    "plan": lambda: self.app.goto("plan")}
        handlers[event.choice_id]()

    def chat_topic(self) -> str:
        if self._request is None:
            return "the approvals"
        return f"{self._request.action} on {store.get_assessment().target}"

    # --- approve: one step, or a double check for HIGH risk ----------------------------------
    def action_approve(self) -> None:
        req = self._request
        if req is None:
            return
        if not self._high:
            self._approve(None)
            return
        try:
            token = store.request_confirmation(req.request_id, req.command_hash)
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        dialog = ChoiceScreen(
            "◆ HIGH-RISK · second confirmation", "Run this HIGH-risk step now?",
            [
                Choice("no", "No, go back", "Nothing runs."),
                Choice("yes", f"Yes, run {self._mask(req.action)} on "
                       f"{self._mask(store.get_assessment().target)}",
                       "Runs this one request now.", "danger"),
            ],
            body=self._confirmation_body(), default=0, danger=True, chip="HIGH RISK",
        )
        self.app.push_screen(dialog, lambda answer: self._confirmed(answer, token))

    def _confirmed(self, answer: Optional[str], token: str) -> None:
        if answer == "yes":
            self._approve(token)
        else:
            store.decline_confirmation(self._request.request_id)

    def _approve(self, token: Optional[str]) -> None:
        req = self._request
        try:
            store.approve(req.request_id, command_hash=req.command_hash,
                          confirmation_token=token)
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        self.app.gate_decided("execution")

    def _confirmation_body(self) -> List[Text]:
        self._masked = False
        req = self._request
        body = [
            Text.assemble(("$ ", f"bold {theme.GREEN}"), (self._mask(req.command), theme.TEXT)),
            Text(req.command_hash, style=theme.DIM),
            Text(""),
            Text.assemble(("Purpose  ", theme.DIM), (self._mask(req.purpose), theme.TEXT)),
            Text.assemble(("Impact   ", theme.DIM), (self._mask(req.impact), theme.MUTED)),
        ]
        if self._masked:
            body.append(Text(MASKED_NOTE, style=theme.DIM))
        return body

    def action_edit(self) -> None:
        if self._request is not None:
            self.app.edit_approval(self._request.request_id)

    def action_reject(self) -> None:
        if self._request is None:
            return
        try:
            store.reject(self._request.request_id)
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        self.app.gate_decided("execution")

    def action_later(self) -> None:
        if self._request is not None:
            self.notify("Nothing runs until you decide. Come back with 4 or /approval.",
                        title="Paused")
            self.app.goto("execution")
        else:
            self.app.go_prev()

    # --- details -----------------------------------------------------------------------------
    def action_details(self) -> None:
        if self._request is None:
            return
        store.log_event("approval.details_viewed", self._request.request_id)
        self.app.push_screen(ChoiceScreen(
            "▤ APPROVAL DETAILS", "", [Choice("back", "Back to the choices")],
            body=self._details_body(), chip="Details",
        ))

    def _details_body(self) -> List[RenderableType]:
        self._masked = False
        req = self._request
        scope = store.describe_scope(store.get_scope())
        events = [e for e in store.list_events() if req.request_id in e.detail]
        blocked = [v for v in store.list_verdicts() if not v.allowed]
        body = details_body([
            ("Request", [
                ("id", req.request_id, theme.KEY),
                ("risk", req.risk, theme.RISK.get(req.risk, theme.MUTED)),
                ("action", self._mask(req.action), theme.TEXT),
                ("purpose", self._mask(req.purpose), theme.MUTED),
                ("impact", self._mask(req.impact), theme.MUTED),
            ]),
            ("Exact request", [
                ("command", self._mask(req.command), theme.TEXT),
                ("hash", req.command_hash, theme.MUTED),
            ]),
            ("Scope limits", [("", self._mask(scope.headline), theme.TEXT)]
             + [("may do", self._mask(item), theme.MUTED) for item in scope.may_do]
             + [("never touches", self._mask(item), theme.CRITICAL) for item in scope.never]
             + [("tools", self._mask(", ".join(scope.tools)), theme.MUTED)]),
            ("Blocked by policy", [
                (v.method, f"{self._mask(v.path)} · {self._mask(v.reason)}", theme.CRITICAL)
                for v in blocked
            ] or [("", "nothing blocked so far", theme.DIM)]),
            ("Audit trail", [
                (e.created_at.strftime("%H:%M:%S"), self._mask(f"{e.kind} · {e.operator}"),
                 theme.MUTED)
                for e in events[-6:]
            ] or [("", "no events for this request yet", theme.DIM)]),
        ])
        if self._masked:
            body.append(Text(MASKED_NOTE, style=theme.DIM))
        return body
