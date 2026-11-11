"""Frame 07 — Finding detail (evidence + analysis, triage, previous / next)."""

from typing import List, Optional, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from .base import ReconixScreen
from .. import store, theme
from ..models import Finding
from ..widgets.findings import (
    confidence_text,
    cvss_text,
    for_display,
    mask,
    severity_text,
    triage_text,
    validation_text,
)


def _heading(text: str, color: str) -> Static:
    return Static(Text(text, style=f"bold {color}"))


def _para(text: str, color: str = theme.MUTED) -> Static:
    return Static(Text(text, style=color))


def _url(url: str, color: str = theme.CYAN) -> Static:
    """A URL the terminal makes clickable (ctrl/cmd+click opens it in the browser)."""
    if url.startswith(("http://", "https://")):
        return Static(Text(url, style=f"link {url} {color}"))
    return _para(url, color)


class FindingDetailScreen(ReconixScreen):
    flow_name = "detail"
    mode_name = "DETAIL"

    BINDINGS = [
        Binding("t", "triage", "triage"),
        Binding("r", "report", "report"),
        Binding("c", "chat", "chat"),
        Binding("left_square_bracket", "step(-1)", "previous finding", show=False),
        Binding("right_square_bracket", "step(1)", "next finding", show=False),
        Binding("left", "to_list", "back to list"),
        Binding("escape", "to_list", "back", show=False),
    ]

    def _finding(self) -> Optional[Finding]:
        try:
            return store.get_finding(self.app.selected_finding)
        except store.StoreValidationError:
            return None

    def view_state(self) -> object:
        f = self._finding()
        return (f.fid, f.status, f.effective_severity, f.triage_note) if f else None

    def compose_body(self) -> ComposeResult:
        f = self._finding()
        if f is None:
            yield Static(
                Text.assemble(
                    ("← findings", theme.CYAN),
                    ("  ·  no finding selected — open one from the list", theme.DIM),
                ),
                id="breadcrumb",
            )
            return
        order, inside = self._order()
        position = order.index(f.fid) + 1
        where = (
            f"({position} of {len(order)})"
            if inside
            else f"(outside filter · {position} of {len(order)})"
        )
        yield Static(
            Text.assemble(
                ("← findings", theme.CYAN),
                ("  /  ", theme.BORDER),
                (f.fid, f"bold {theme.MUTED}"),
                (f"  {where}", theme.DIM),
                ("  ·  [ prev  ·  ] next", theme.DIM),
            ),
            id="breadcrumb",
        )
        d = for_display(f)  # mask secrets in every shown field (display only)
        with Vertical(classes="panel", id="detail-header"):
            yield Static(
                Text.assemble(
                    severity_text(d),
                    "   ",
                    (d.title, f"bold {theme.TEXT}"),
                    "      ",
                    validation_text(d),
                    "   ",
                    confidence_text(d),
                    "   ",
                    triage_text(d),
                )
            )
            refs = " · ".join(d.cve + d.cwe + d.owasp) or "—"
            yield Static(
                Text.assemble(
                    (f"{d.fid} · {d.path} · detected by {d.tool}", theme.MUTED),
                    "    ",
                    (f"CVSS {cvss_text(d)} · {refs}", theme.KEY),
                )
            )
        with Horizontal(id="detail-cols"):
            with Vertical(classes="panel") as evidence:
                evidence.border_title = "▤ EVIDENCE"
                evidence.border_subtitle = Text(d.tool)  # imported text: never markup
                yield _heading("Affected URL", theme.DIM)
                yield _url(d.affected_url, theme.CYAN)
                if d.evidence_summary:
                    yield Static("")
                    yield _heading("What the evidence shows", theme.DIM)
                    yield _para(d.evidence_summary, theme.TEXT)
                yield Static("")
                yield _heading("Evidence (masked)", theme.DIM)
                for line in d.evidence:
                    yield _para(line, theme.STRING)
                if not d.evidence:
                    yield _para("—", theme.DIM)
                yield Static("")
                yield _heading("Validation", theme.DIM)
                if d.needs_review:
                    note = (
                        f"○ {d.validation.title()} — needs analyst review. Press t to set "
                        "its status.",
                        theme.MEDIUM,
                    )
                else:
                    by = f" by {d.validation_method}" if d.validation_method else ""
                    note = (
                        f"✓ Confirmed during the run{by} by the limited validation you approved.",
                        theme.TEAL,
                    )
                yield Static(Text(*note), classes="panel-note")
                if d.validation_reason:
                    yield _para(d.validation_reason, theme.DIM)
            with Vertical(classes="panel") as analysis:
                analysis.border_title = "✦ AI ANALYSIS"
                analysis.border_subtitle = "grounded in OWASP · CWE · NVD"
                yield _heading("Description", theme.TEXT)
                yield _para(d.description)
                yield Static("")
                yield _heading("Impact", theme.HIGH)
                yield _para(d.impact)
                yield Static("")
                yield _heading("Remediation", theme.TEAL)
                yield _para(d.remediation)
                yield Static("")
                yield _heading("Classification", theme.LOW)
                yield _para(f"{d.category or '—'} · {d.cvss_vector or 'not scored'}")
                for ref in d.references:
                    yield Static(Text.assemble(("• ", theme.DIM), (ref, theme.KEY)))
                if d.triage_note:
                    yield Static("")
                    yield _heading("Triage note", theme.MEDIUM)
                    yield _para(d.triage_note)

    # --- previous / next in the Findings list order -----------------------------------------
    def _order(self) -> Tuple[List[str], bool]:
        """Finding ids in the list's filter+sort order, and whether this finding is in it."""
        app = self.app
        order = [f.fid for f in store.find_findings(app.findings_filter, app.findings_sort)]
        if app.selected_finding in order:
            return order, True
        # Opened via /finding, or triaged out of the filter: walk everything instead.
        return [f.fid for f in store.find_findings("all", app.findings_sort)], False

    def action_step(self, delta: int) -> None:
        if self._finding() is None:
            return
        order, _ = self._order()
        position = order.index(self.app.selected_finding) + delta
        if not 0 <= position < len(order):
            self.app.bell()  # at an end: no wrap-around
            return
        self.app.open_finding(order[position])

    def action_triage(self) -> None:
        if self._finding() is not None:
            self.app.triage_finding(self.app.selected_finding)

    def action_chat(self) -> None:
        """Chat about the open finding; the draft names it (plain text, never markup)."""
        finding = self._finding()
        self.chat_about(f"About {finding.fid} {mask(finding.title)}: " if finding else "")

    def action_report(self) -> None:
        self.app.goto("report")

    def action_to_list(self) -> None:
        self.app.goto("findings")
