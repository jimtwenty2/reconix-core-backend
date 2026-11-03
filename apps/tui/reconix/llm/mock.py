"""Flexible LLM: the offline mock model (`reconix-mock-1`).

A provider for testing without a model or a network: `reply()` picks a prepared answer from
`mock_replies.json` and fills it with the assessment's own facts. Pure (no I/O after the
replies file is read once), so it is instant and never leaves this computer. The web has a
port of this file (`apps/web/src/lib/assistant/models/mock.ts`) reading a copy of the same
JSON; change both together.

`facts` is a plain dict:
    target, scope, step, plan: str ("" when there is none yet); plan is "1. … ; 2. …; 3a. …"
    findings: list of {id, severity, title, impact, remediation, status}
"""

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Pattern, Sequence, Tuple

MOCK_MODEL = "reconix-mock-1"
REPLIES_FILE = Path(__file__).with_name("mock_replies.json")

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")
# A step-chat line arrives as "About <topic>: <question>"; only the question is matched.
_ABOUT = re.compile(r"^About [^:\n]{1,80}:\s*")
_PLACEHOLDER = re.compile(r"\{(\w+)\}")

Intent = Tuple[str, Tuple[Pattern, ...], dict]


@lru_cache(maxsize=1)
def _load() -> Tuple[Tuple[Intent, ...], str]:
    data = json.loads(REPLIES_FILE.read_text(encoding="utf-8"))
    intents = tuple(
        (item["id"], tuple(re.compile(p, re.IGNORECASE) for p in item["patterns"]), item)
        for item in data["intents"]
    )
    return intents, data["fallback"]


def intent_of(question: str) -> Tuple[str, Optional[str]]:
    """The intent id that answers `question` ("fallback" when none), and a captured value."""
    text = _ABOUT.sub("", question or "").strip()
    intents, _ = _load()
    for intent_id, patterns, _item in intents:
        for pattern in patterns:
            found = pattern.search(text)
            if found:
                captured = found.group(1) if found.groups() else None
                return intent_id, captured
    return "fallback", None


def reply(question: str, facts: Optional[Mapping[str, object]] = None) -> str:
    """The mock's answer to `question`, filled in from `facts`."""
    facts = facts or {}
    intent_id, captured = intent_of(question)
    intents, fallback = _load()
    if intent_id == "fallback":
        return fallback
    item = next(entry for iid, _p, entry in intents if iid == intent_id)
    values = _values(facts)
    needs = item.get("needs")
    if needs == "finding":
        return _finding_reply(item, facts, captured or "", values)
    if needs == "plan_step":
        return _plan_step_reply(item, captured or "", values)
    if needs and not values.get(needs):
        return _fill(item["empty"], values)
    return _fill(item["reply"], values)


def _finding_reply(
    item: dict, facts: Mapping[str, object], wanted: str, values: Dict[str, str]
) -> str:
    findings = _findings(facts)
    if not findings:
        return _fill(item["empty"], values)
    fid = wanted.zfill(3)
    match = next((f for f in findings if str(f.get("id", "")).zfill(3) == fid), None)
    if match is None:
        return _fill(item["missing"], {**values, "id": fid})
    return _fill(item["reply"], {**values, **{k: str(v) for k, v in match.items()}})


def _plan_step_reply(item: dict, wanted: str, values: Dict[str, str]) -> str:
    """One row of the plan ("what does step 2 do?"), not the whole plan."""
    rows = [row.strip() for row in values["plan"].split(";") if row.strip()]
    if not rows:
        return _fill(item["empty"], values)
    wanted = wanted.casefold()
    for row in rows:
        number, dot, rest = row.partition(". ")
        if dot and number.casefold() == wanted:
            return _fill(item["reply"], {**values, "row": f"{number}: {rest}"})
    return _fill(item["missing"], {**values, "id": wanted})


def _findings(facts: Mapping[str, object]) -> List[Mapping[str, object]]:
    found = facts.get("findings") or []
    return [f for f in found if isinstance(f, Mapping)] if isinstance(found, Sequence) else []


def _values(facts: Mapping[str, object]) -> Dict[str, str]:
    findings = _findings(facts)
    values = {key: str(facts.get(key) or "") for key in ("target", "scope", "step", "plan")}
    values["step"] = values["step"] or "Type a target to start an assessment."
    values["finding"] = "yes" if findings else ""
    values["findings"] = "yes" if findings else ""
    if findings:
        ranked = sorted(findings, key=_rank)
        top = ranked[0]
        values["top"] = f"{top.get('id')} {top.get('severity')} {top.get('title')}"
        values["top_id"] = str(top.get("id"))
        values["count"] = _count(findings)
        values["list"] = "; ".join(
            f"{f.get('id')} {f.get('severity')} {f.get('title')}" for f in findings
        )
        values["ids"] = ", ".join(str(f.get("id")) for f in findings)
    return values


def _rank(finding: Mapping[str, object]) -> int:
    severity = str(finding.get("severity", "")).upper()
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _count(findings: Sequence[Mapping[str, object]]) -> str:
    by: Dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "")).upper()
        by[severity] = by.get(severity, 0) + 1
    parts = [f"{by[s]} {s}" for s in SEVERITY_ORDER if s in by]
    noun = "finding" if len(findings) == 1 else "findings"
    return f"{len(findings)} {noun} ({', '.join(parts)})"


def _fill(template: str, values: Mapping[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), ""), template).strip()
