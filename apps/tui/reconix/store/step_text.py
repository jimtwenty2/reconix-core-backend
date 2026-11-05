"""A step's content in plain text: Reconix's first reply when you pick "Chat about this".

The Template/Scope, Plan and Approval screens open a chat inside the step; its first line
is what the step shows, written out (like Claude Code printing a plan before you discuss
it). Plain strings only: the screen draws them as Rich Text, never as markup.
"""

from typing import List

from . import lists
from .approvals import get_approval
from .plan import plan_overview
from .scope_view import describe_scope, join_and
from .templates import catalog, selected_template


def scope_text() -> str:
    """The scope manifest: target, what it may do, ports or methods, tools and limits."""
    scope = lists.current().scope
    if scope is None:
        return "No scope yet: pick a template and type its target first."
    summary = describe_scope(scope)
    state = "approved · locked" if scope.status == "APPROVED" else "draft · waits for your approval"
    lines: List[str] = [
        f"Scope · {scope.target_url} ({scope.assessment_type}) · {state}",
        summary.headline,
    ]
    lines += [f"  · {item}" for item in summary.may_do]
    if scope.kind == "network":
        lines.append(f"Ports: {join_and(scope.allowed_ports) or 'none'}")
    else:
        lines.append(f"Methods: {join_and(scope.allowed_methods)}")
    if summary.never:
        lines.append(f"Never touches: {join_and(summary.never)}")
    _limit = f"{scope.time_limit_minutes} min" if scope.time_limit_minutes > 0 else "no limit"
    lines.append(f"Tools: {join_and(scope.tools)} · time limit {_limit}")
    return "\n".join(lines)


def plan_text() -> str:
    """The plan's steps, numbered as the Plan screen lists them, with their gates."""
    rows = plan_overview()
    if not rows:
        return "No plan yet: approve the scope first."
    assessment = lists.current()
    template = selected_template()
    lines: List[str] = [f"Plan · {template.name if template else 'template'} · {assessment.target}"]
    for row in rows:
        line = f"{row.num}. {row.label}"
        if row.detail:
            line += f" - {row.detail}"
        if row.gate == "approve":
            line += f"  [{row.risk} · needs your approval]"
        elif row.gate == "login":
            line += "  [needs the target login]"
        if row.status != "pending":
            line += f" ({row.status})"
        lines.append(line)
    return "\n".join(lines)


def approval_text(request_id: str) -> str:
    """One gated action: what it does, where, its risk and why it waits for you."""
    request = get_approval(request_id)
    return "\n".join(
        [
            f"Approval · {request.action} · {request.risk} risk",
            f"Target: {request.target}",
            f"Purpose: {request.purpose}",
            f"Impact: {request.impact}",
            "It waits for your decision: nothing runs until you approve it.",
        ]
    )


def template_text() -> str:
    """The templates to pick from, the suggested one marked."""
    lines = ["Templates:"]
    for template in catalog():
        mark = "  (suggested)" if template.suggested else ""
        lines.append(f"  · {template.name} - {template.description}{mark}")
    return "\n".join(lines)
