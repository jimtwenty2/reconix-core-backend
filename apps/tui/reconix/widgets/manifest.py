"""The scope manifest in plain words (Template screen): what Reconix may and won't do."""

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static

from .. import store, theme
from ..models import ScopeManifest


def manifest_text(scope: ScopeManifest, *, with_suggestions: bool = True) -> Text:
    """The store's plain-language summary. Built as Text, so a typed target is never markup.

    `with_suggestions` draws the read-only "Suggested for your goal" section. The Scope
    review screen passes False, because it shows those tools as an interactive tick list
    instead, and the card must not list them twice."""
    summary = store.describe_scope(scope)
    text = Text(summary.headline, style=theme.TEXT)
    if scope.target_url.startswith(("http://", "https://")):
        text.append("\nTarget  ", style=f"bold {theme.TEXT}")
        text.append(scope.target_url, style=f"link {scope.target_url} {theme.CYAN}")
        text.append("  (ctrl+click to open)", style=theme.DIM)
    reading = store.scope_reading()
    if reading:
        text.append("\n\nYour goal", style=f"bold {theme.TEXT}")
        text.append(f"\n  {reading}", style=theme.MUTED)
    text.append("\n\nWhat it may do", style=f"bold {theme.TEXT}")
    for item in summary.may_do:
        text.append("\n  ✓ ", style=theme.GREEN)
        text.append(item, style=theme.MUTED)
    if summary.never:
        text.append("\n\nWhat it will never touch", style=f"bold {theme.TEXT}")
        for item in summary.never:
            text.append("\n  ✗ ", style=theme.CRITICAL)
            text.append(item, style=theme.MUTED)
    if summary.tools:
        text.append("\n\nTools it will use: ", style=f"bold {theme.TEXT}")
        text.append(", ".join(summary.tools), style=theme.MUTED)
    notes = store.suggested_tool_notes() if with_suggestions else []
    if notes:
        text.append("\n\nSuggested for your goal", style=f"bold {theme.GREEN}")
        text.append("  (Edit manifest to add — one per job)", style=theme.DIM)
        for tool, purpose in notes:
            text.append("\n  + ", style=theme.GREEN)
            text.append(tool, style=theme.GREEN)
            if purpose:
                text.append(f" — {purpose}", style=theme.MUTED)
    _techniques(text, scope.kind)
    text.append("\nTime limit: ", style=f"bold {theme.TEXT}")
    limit = f"{scope.time_limit_minutes} min" if scope.time_limit_minutes > 0 else "no limit"
    text.append(limit, style=theme.MUTED)
    spec = store.get_api_spec() if scope.kind == "api" else None
    if spec is not None:
        text.append("\n\nAPI spec  ", style=f"bold {theme.TEXT}")
        text.append(f"{spec.label} · {spec.total} endpoints · {', '.join(spec.methods)}",
                    style=theme.MUTED)
        outside = store.api_spec_methods_outside()
        if outside:
            text.append("\nIn spec, not allowed  ", style=f"bold {theme.TEXT}")
            text.append(", ".join(outside), style=theme.MEDIUM)
        if spec.out_of_scope_servers:
            text.append("\nOut of scope  ", style=f"bold {theme.TEXT}")
            text.append(", ".join(spec.out_of_scope_servers), style=theme.MEDIUM)
    return text


# The scope card's technique groups: (mode, glyph, color token, label).
TECHNIQUE_GROUPS = (
    ("auto", "✓", "GREEN", "tested by the tools"),
    ("partial", "◐", "MEDIUM", "partly; finish by hand"),
    ("manual", "○", "DIM", "you check by hand"),
)


def _techniques(text: Text, kind: str) -> None:
    """What the template tests: one line per group, so the card stays short."""
    groups = store.technique_groups(kind)
    if not any(groups.values()):
        return
    text.append("\n\nTechniques", style=f"bold {theme.TEXT}")
    for mode, glyph, color, label in TECHNIQUE_GROUPS:
        names = groups.get(mode, [])
        if names:
            text.append(f"\n  {glyph} ", style=getattr(theme, color))
            text.append(f"{label}: ", style=theme.TEXT)
            text.append(", ".join(names), style=theme.MUTED)


class ScopeManifestView(Static):
    """The manifest body; call `show(scope)` to redraw after an edit."""

    def __init__(self, scope: ScopeManifest, *, with_suggestions: bool = True, **kwargs) -> None:
        self._with_suggestions = with_suggestions
        super().__init__(manifest_text(scope, with_suggestions=with_suggestions), **kwargs)

    def show(self, scope: ScopeManifest) -> None:
        self.update(manifest_text(scope, with_suggestions=self._with_suggestions))


class ScopePanel(Vertical):
    """The ⛉ SCOPE card: the manifest in a bordered panel, marked draft or approved.

    The Template screen shows it, and so does the step chat whenever the scope is new or
    changed, so both always draw the same card."""

    def __init__(self, scope: ScopeManifest, *, body_id: str = "",
                 with_suggestions: bool = True, **kwargs) -> None:
        approved = scope.status == "APPROVED"
        super().__init__(classes="panel success" if approved else "panel accent", **kwargs)
        self.border_title = "⛉ SCOPE"
        self.border_subtitle = "approved · locked" if approved else "draft · needs your approval"
        self._scope = scope
        self._body_id = body_id or None
        self._with_suggestions = with_suggestions

    def compose(self) -> ComposeResult:
        yield ScopeManifestView(self._scope, with_suggestions=self._with_suggestions,
                                classes="panel-body", id=self._body_id)
