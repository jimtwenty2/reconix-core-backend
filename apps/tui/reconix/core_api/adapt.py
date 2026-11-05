"""The one place Core API values become the app's values (apps/CLAUDE.md "Data").

ERD V3 enums stay UPPERCASE (severity, validation, risk). Only the app's own words are
translated here: the triage status (open, false-positive, fixed) and the progress bar a
step's purpose fills. A severity the app has no colour for is kept, never dropped: NONE
(an informational result, such as an open port) and UNKNOWN show as they are.
"""

import shlex
from typing import Dict, List, Optional

from ..models import ApprovalRequest, Finding

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")
# finding_status (API) <-> the app's triage words.
TRIAGE_FROM_API = {"OPEN": "open", "FALSE_POSITIVE": "false-positive", "FIXED": "fixed"}
TRIAGE_TO_API = {word: status for status, word in TRIAGE_FROM_API.items()}
# ActionIn.purpose -> the progress bar the step fills.
PURPOSE_BAR = {"discovery": "discovery", "scan": "scanning", "validation": "validation"}
OUTPUT_LINES = 12  # tool output lines shown on a step's card (the rest is in the evidence)


def severity(value: Optional[str]) -> str:
    value = (value or "UNKNOWN").upper()
    return value if value in SEVERITIES else "UNKNOWN"


def command(action: dict) -> str:
    """The exact tool call the API checked, as one readable line (never run from here)."""
    tool = str(action.get("tool", "")).lower()
    return shlex.join(
        [tool, *[str(a) for a in action.get("args") or []], str(action.get("target", ""))]
    )


def bar(action: dict) -> str:
    return PURPOSE_BAR.get(str(action.get("purpose") or ""), "scanning")


def step_title(step: Optional[dict], action: dict) -> str:
    """What the step is called: the plan's title for it, else the tool and target."""
    if step and step.get("title"):
        return str(step["title"])
    return f"{str(action.get('tool', '')).lower()} on {action.get('target', '')}"


def approval_request(action: dict, approval: dict, step: Optional[dict]) -> ApprovalRequest:
    """The approval card for an action the API holds for a person."""
    risk = str(action.get("risk_level") or approval.get("risk_level") or "MEDIUM").upper()
    reason = str((step or {}).get("reason") or "")
    return ApprovalRequest(
        request_id=str(approval["approval_id"]),
        risk=risk,
        action=step_title(step, action),
        target=str(action.get("target", "")),
        method=str(action.get("tool", "")),
        path=str(action.get("target", "")),
        purpose=reason or f"The AI's next step in the plan ({action.get('purpose', 'scan')})",
        impact=(
            "Runs one tool call in Kali against the target; it waits for you because its "
            f"risk is {risk}."
        ),
        command=command(action),
        command_hash=f"sha256:{approval.get('subject_hash', '')}",
        api_approval_id=str(approval["approval_id"]),
    )


def output_rows(text: str) -> List[tuple]:
    """The first lines of a tool's masked output, for its card."""
    lines = [line.rstrip() for line in (text or "").splitlines() if line.strip()]
    rows = [("", line[:160]) for line in lines[:OUTPUT_LINES]]
    if len(lines) > OUTPUT_LINES:
        rows.append(("", f"… {len(lines) - OUTPUT_LINES} more lines"))
    return rows


def finding(row: dict, fid: str) -> Finding:
    """A FindingOut as the app's Finding. The evidence is already masked by the API."""
    references = [*row.get("cwe_ids", []), *row.get("owasp_id", []), *row.get("cve_ids", [])]
    tools = row.get("tools") or []
    cvss = row.get("cvss_score")
    return Finding(
        fid=fid,
        severity=severity(row.get("severity_status")),
        title=str(row.get("title", "")),
        path=str(row.get("target", "")),
        validation=str(row.get("validation_status") or "UNCONFIRMED").upper(),
        description=str(row.get("description") or ""),
        affected_url=str(row.get("target", "")),
        impact=str(row.get("impact") or ""),
        remediation=str(row.get("remediation") or ""),
        tool=str(tools[0]).lower() if tools else "",
        references=[str(r) for r in references],
        evidence=[str(e.get("content") or "") for e in row.get("evidence", []) if e.get("content")],
        cvss_score=float(cvss) if cvss is not None else 0.0,
        category=str(row.get("code", "")),
        status=TRIAGE_FROM_API.get(str(row.get("finding_status") or "OPEN"), "open"),
    )


def plan_step_for(steps: List[dict], action: dict, position: int) -> Optional[dict]:
    """The plan row an action came from: the row at its place in the run (`position`, from
    1) when it is the same tool and target, else None (a step the agent chose later)."""
    if 0 < position <= len(steps):
        planned = steps[position - 1].get("action") or {}
        if (str(planned.get("tool", "")).upper() == str(action.get("tool", "")).upper()
                and planned.get("target") == action.get("target")):
            return steps[position - 1]
    return None


def tool_run_line(action: dict) -> Dict[str, str]:
    """The newest tool run of an action: status, exit code, error and output."""
    runs = action.get("tool_runs") or []
    if not runs:
        return {}
    run = runs[-1]
    return {
        "status": str(run.get("tool_run_status") or ""),
        "exit": "" if run.get("exit_code") is None else str(run["exit_code"]),
        "error": str(run.get("error") or ""),
        "output": str(run.get("output_masked") or ""),
    }
