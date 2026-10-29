"""Reads the model's report text.

Only two texts come from the model: the executive summary and the methodology.
The findings, their severity, the counts and the approvals in a report always
come from the locked copy the API sends, never from the model.
"""

from typing import Any

from reconix_ai.agent.answers import BadAnswer

MAX_REPORT_TEXT_CHARS = 4000


def read_report(data: dict[str, Any]) -> tuple[str, str]:
    """The executive summary and the methodology, both required."""
    return report_text(data, "executive_summary"), report_text(data, "methodology")


def report_text(data: dict[str, Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value.strip():
        raise BadAnswer(f"no {name}")
    return value.strip()[:MAX_REPORT_TEXT_CHARS]
