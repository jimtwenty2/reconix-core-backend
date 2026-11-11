"""The one place Core API values become the app's values (apps/CLAUDE.md "Data").

ERD V3 enums stay UPPERCASE (severity, validation, risk). Only the app's own words are
translated here: the triage status (open, false-positive, fixed) and the progress bar a
step's purpose fills. A severity the app has no colour for is kept, never dropped: NONE
(an informational result, such as an open port) and UNKNOWN show as they are.
"""

import json
import shlex
from typing import Any, Dict, List, Optional

from ..models import ApprovalRequest, Finding

# The AI's plain reading of the proof is kept as an evidence row of this kind (see the API's
# analysis service); every other evidence row is the raw proof.
SUMMARY_KIND = "analysis_summary"

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
        rows.append(
            (
                "",
                f"… {len(lines) - OUTPUT_LINES} more lines · Ctrl+O expands the log; "
                "the full output is on the finding",
            )
        )
    return rows


def _label(key: str) -> str:
    """A JSON proof key as a human label: "matched-at" -> "Matched at"."""
    return str(key).replace("-", " ").replace("_", " ").strip().capitalize()


def _value(value: Any) -> str:
    """A JSON proof value as one plain string; a list joins, a dict reads as key-value pairs."""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if str(item))
    if isinstance(value, dict):
        return "; ".join(f"{_label(key)}: {item}" for key, item in value.items())
    return str(value)


def humanize_evidence(content: str) -> List[str]:
    """Turn one stored evidence blob into human lines. A JSON proof dict becomes
    "Label: value" lines so a reader never sees a JSON blob; a list becomes its items;
    plain text (a text reader's output) is shown as it is."""
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return [content]
    if isinstance(data, dict):
        return [f"{_label(key)}: {_value(item)}" for key, item in data.items() if _value(item)]
    if isinstance(data, list):
        return [_value(item) for item in data if _value(item)]
    return [content]


def finding(row: dict, fid: str) -> Finding:
    """A FindingOut as the app's Finding. The evidence is already masked by the API; here the
    raw JSON proof becomes plain lines, the AI's reading of it is pulled out of its own
    evidence row, and the latest validation's plain reason is carried for the detail view."""
    references = [*row.get("cwe_ids", []), *row.get("owasp_id", []), *row.get("cve_ids", [])]
    tools = row.get("tools") or []
    cvss = row.get("cvss_score")
    summary = ""
    proof: List[str] = []
    for item in row.get("evidence", []):
        content = str(item.get("content") or "")
        if not content:
            continue
        if str(item.get("kind") or "") == SUMMARY_KIND:
            summary = content
        else:
            proof.extend(humanize_evidence(content))
    validation = row.get("latest_validation") or {}
    return Finding(
        fid=fid,
        severity=severity(row.get("severity_status")),
        title=str(row.get("title", "")),
        path=str(row.get("target", "")),
        validation=str(row.get("validation_status") or "UNCONFIRMED").upper(),
        confidence=str(row.get("confidence") or "TENTATIVE").upper(),
        description=str(row.get("description") or ""),
        affected_url=str(row.get("target", "")),
        impact=str(row.get("impact") or ""),
        remediation=str(row.get("remediation") or ""),
        tool=str(tools[0]).lower() if tools else "",
        references=[str(r) for r in references],
        evidence=proof,
        evidence_summary=summary,
        validation_reason=str(validation.get("reason") or ""),
        validation_method=str(validation.get("method") or ""),
        cvss_score=float(cvss) if cvss is not None else 0.0,
        category=str(row.get("code", "")),
        status=TRIAGE_FROM_API.get(str(row.get("finding_status") or "OPEN"), "open"),
    )


def code_finding(row: dict, fid: str) -> Finding:
    """A CodeFindingOut as the app's Finding: where it is (path:line), the rule, the masked
    first line as proof, and the AI review's verdict, explanation and fix. A CONFIRMED
    verdict (only a validation gives it) is shown as validated; every other stays as the API
    says it (UNCONFIRMED), never upgraded here."""
    found = finding(row, fid)
    path, line = str(row.get("path") or ""), row.get("line")
    where = f"{path}:{line}" if path and line else path or found.path
    verdict = str(row.get("verdict") or "UNVERIFIED").upper()
    snippet = str(row.get("snippet") or "")
    rule = str(row.get("rule_id") or "")
    found.title = found.title or rule
    found.path = found.affected_url = where
    found.category = "Source Code"
    found.evidence = [line_ for line_ in (f"Rule: {rule}" if rule else "", snippet) if line_] \
        or found.evidence
    found.evidence_summary = str(row.get("explanation") or found.evidence_summary)
    found.validation_reason = f"AI review: {verdict}"
    found.remediation = str(row.get("fix_recommendation") or found.remediation)
    if verdict == "CONFIRMED":
        found.validation = "CONFIRMED"
    return found


def plan_step_for(steps: List[dict], action: dict, position: int) -> Optional[dict]:
    """The plan row an action came from: the row at its place in the run (`position`, from
    1) when it is the same tool and target, else None (a step the agent chose later)."""
    if 0 < position <= len(steps):
        planned = steps[position - 1].get("action") or {}
        if str(planned.get("tool", "")).upper() == str(
            action.get("tool", "")
        ).upper() and planned.get("target") == action.get("target"):
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
