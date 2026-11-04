"""SARIF (a standard JSON format for findings) -> its results. Only reads; no database, no HTTP.

One reader for every tool that writes SARIF (ZAP, semgrep, gitleaks, trivy, CodeQL…). A
result names its rule by ruleId; the rule (name, description, fix, CWE) is looked up in the
same run's tool.driver.rules.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any

# Request and response bodies (ZAP): large, and kept on the tool run, not as evidence.
HIDDEN = ("webRequest", "webResponse")
CWE_COMPONENT = re.compile(r"^cwe$", re.IGNORECASE)


class SarifParseError(ValueError):
    """The output is empty, cut off or not SARIF."""


@dataclass(frozen=True)
class SarifResult:
    rule_id: str
    title: str
    message: str
    description: str | None
    remediation: str | None
    level: str  # error, warning, note or none
    security_severity: float | None  # 0-10, when the tool gives one
    uri: str
    line: int | None
    cwe_ids: list[str] = field(default_factory=list)
    proof: dict[str, Any] = field(default_factory=dict)  # the result, without HIDDEN


def parse(raw: str) -> list[SarifResult]:
    if not raw or not raw.strip():
        raise SarifParseError("EMPTY_OUTPUT")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SarifParseError(f"NOT_SARIF: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        raise SarifParseError("NOT_SARIF: no runs")
    return [
        _result(result, rules)
        for run in document["runs"]
        if isinstance(run, dict)
        for rules in [_rules(run)]
        for result in _list(run.get("results"))
    ]


def _rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = _dict(_dict(run.get("tool")).get("driver"))
    return {str(rule.get("id")): rule for rule in _list(driver.get("rules"))}


def _result(result: dict[str, Any], rules: dict[str, dict[str, Any]]) -> SarifResult:
    rule_id = str(result.get("ruleId") or "")
    rule = rules.get(rule_id, {})
    properties = _dict(rule.get("properties"))
    location = _dict(_dict(_first(result.get("locations"))).get("physicalLocation"))
    level = result.get("level") or _dict(rule.get("defaultConfiguration")).get("level")
    return SarifResult(
        rule_id=rule_id,
        title=_text(rule.get("name")) or _text(rule.get("shortDescription")) or rule_id,
        message=_text(result.get("message")),
        description=_text(rule.get("fullDescription")) or None,
        remediation=_text(properties.get("solution")) or _text(rule.get("help")) or None,
        level=str(level or "warning").lower(),
        security_severity=_number(properties.get("security-severity")),
        uri=str(_dict(location.get("artifactLocation")).get("uri") or ""),
        line=_line(_dict(location.get("region")).get("startLine")),
        cwe_ids=_cwe_ids(rule),
        proof={name: value for name, value in result.items() if name not in HIDDEN},
    )


def _cwe_ids(rule: dict[str, Any]) -> list[str]:
    """CWE ids from the rule's relationships (ZAP) or its tags (semgrep: "CWE-89: ...")."""
    ids = {
        f"CWE-{target.get('id')}"
        for relation in _list(rule.get("relationships"))
        for target in [_dict(relation.get("target"))]
        if CWE_COMPONENT.match(str(_dict(target.get("toolComponent")).get("name", "")))
        and str(target.get("id", "")).isdigit()
    }
    tags = _dict(rule.get("properties")).get("tags")
    tags = tags if isinstance(tags, list) else []
    ids |= {match.upper() for tag in tags for match in re.findall(r"CWE-\d+", str(tag), re.I)}
    return sorted(ids)


def _text(value: Any) -> str:
    """A SARIF message: {"text": ...} or a plain string."""
    if isinstance(value, dict):
        value = value.get("text")
    return value.strip() if isinstance(value, str) else ""


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _line(value: Any) -> int | None:
    return value if isinstance(value, int) and value > 0 else None


def _first(value: Any) -> Any:
    items = _list(value)
    return items[0] if items else None


def _list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
