"""Reads the model's analysis and holds it to the 8 rules of workflow v5.

The model only suggests, and the rules are enforced here, not trusted to the
prompt: an unknown finding is dropped, a severity is one of the six values, the
evidence must be copied from the tool output, an id must come from the finding
or the knowledge (never from a banner the target wrote), and a next step is a
well-formed action. Whether that action is allowed is the harness's call, made
in the analyze node.
"""

import re
from typing import Any

from reconix_ai.agent.answers import MAX_SUMMARY_CHARS, BadAnswer, read_action
from reconix_ai.contracts import SEVERITY_ORDER

SEVERITIES = set(SEVERITY_ORDER)
VERDICTS = {"CONFIRMED", "UNCONFIRMED", "INCONCLUSIVE"}  # validation_runs.validation_status
MAX_TEXT_CHARS = 1500
MIN_EVIDENCE_CHARS = 8  # shorter text is found almost anywhere
MAX_IDS = 10
ID_PATTERNS = {
    "cwe_ids": re.compile(r"CWE-\d+"),
    "owasp_id": re.compile(r"(?:A\d{2}|API\d{1,2}):\d{4}"),
    "cve_ids": re.compile(r"CVE-\d{4}-\d{4,}"),
}
NO_ANALYSIS = "The model gave no analysis for this finding."
NO_EVIDENCE = "The evidence the model gave is not in the tool output, so it was left out."


def read_analysis(
    data: dict[str, Any],
    findings: list[dict[str, Any]],
    tool_results: list[str],
    known_ids: set[str],
) -> tuple[str, list[dict[str, Any]]]:
    """The summary and one analysis per input finding, in the input order.

    known_ids are the ids found in the knowledge hits; with each finding's own
    ids they are the only ids a mapping may use.
    """
    raw = data.get("findings")
    if not isinstance(raw, list):
        raise BadAnswer("no findings")
    by_code = {}
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("code"), str):
            by_code.setdefault(item["code"].strip(), item)  # the first answer for a code wins
    codes = [finding["code"] for finding in findings]
    if not set(codes) & set(by_code):
        raise BadAnswer("no known finding")
    analyses = [
        read_one(by_code.get(finding["code"]), finding, codes, tool_results, known_ids)
        for finding in findings
    ]
    return text(data.get("summary"), MAX_SUMMARY_CHARS), analyses


def read_validation(data: dict[str, Any]) -> tuple[str, str]:
    """The verdict on one PoC run: (validation_status, reason). The status must be one of
    the three values; anything else is a bad answer, so the node asks once more then fails
    rather than guess a verdict for a security decision."""
    verdict = data.get("verdict")
    status = verdict.strip().upper() if isinstance(verdict, str) else ""
    if status not in VERDICTS:
        raise BadAnswer("no verdict")
    return status, text(data.get("reason"), MAX_TEXT_CHARS)


def read_one(
    raw: dict[str, Any] | None,
    finding: dict[str, Any],
    codes: list[str],
    tool_results: list[str],
    known_ids: set[str],
) -> dict[str, Any]:
    if raw is None:
        return empty_analysis(finding["code"])
    unsure = [text(raw.get("unsure"), MAX_TEXT_CHARS)]
    evidence = text(raw.get("evidence"), MAX_TEXT_CHARS)
    if evidence and not is_copied(evidence, tool_results):
        evidence = ""
        unsure.append(NO_EVIDENCE)
    allowed_ids = known_ids | {i for name in ID_PATTERNS for i in finding.get(name, [])}
    return {
        "code": finding["code"],
        "explanation": text(raw.get("explanation"), MAX_TEXT_CHARS),
        "related": related_codes(raw.get("related"), finding["code"], codes),
        "severity_status": severity(raw.get("severity_status")),
        "cvss_score": cvss(raw.get("cvss_score")),
        "evidence": evidence,
        "impact": text(raw.get("impact"), MAX_TEXT_CHARS),
        "remediation": text(raw.get("remediation"), MAX_TEXT_CHARS),
        **{name: mapped_ids(raw.get(name), name, allowed_ids) for name in ID_PATTERNS},
        "next_step": next_step(raw.get("next_step")),
        "unsure": " ".join(note for note in unsure if note),
    }


def empty_analysis(code: str) -> dict[str, Any]:
    return {
        "code": code,
        "explanation": "",
        "related": [],
        "severity_status": "UNKNOWN",
        "cvss_score": None,
        "evidence": "",
        "impact": "",
        "remediation": "",
        "cwe_ids": [],
        "owasp_id": [],
        "cve_ids": [],
        "next_step": None,
        "unsure": NO_ANALYSIS,
    }


def is_copied(evidence: str, tool_results: list[str]) -> bool:
    """Long enough to mean something, and found whole in one tool result."""
    return len(evidence) >= MIN_EVIDENCE_CHARS and any(evidence in r for r in tool_results)


def text(value: Any, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def related_codes(value: Any, own_code: str, codes: list[str]) -> list[str]:
    if not isinstance(value, list):
        return []
    known = [code for code in value if isinstance(code, str) and code in codes]
    return [code for code in dict.fromkeys(known) if code != own_code]


def severity(value: Any) -> str:
    if isinstance(value, str) and value.strip().upper() in SEVERITIES:
        return value.strip().upper()
    return "UNKNOWN"


def cvss(value: Any) -> float | None:
    # bool is an int in Python; true is not a score.
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if 0.0 <= value <= 10.0 else None


def mapped_ids(value: Any, name: str, allowed: set[str]) -> list[str]:
    if not isinstance(value, list):
        return []
    ids = [i.strip().upper() for i in value if isinstance(i, str)]
    kept = [i for i in ids if ID_PATTERNS[name].fullmatch(i) and i in allowed]
    return list(dict.fromkeys(kept))[:MAX_IDS]


def next_step(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    action = read_action(value.get("tool"), value.get("target"), value.get("arguments", []))
    if action is None:
        return None
    return {**action, "is_validation": True}  # it confirms a finding
