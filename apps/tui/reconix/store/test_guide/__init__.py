"""The evaluator test guide: every flow and case, one source for /tests and the docs.

`list_flows()` is what the /tests screen lists and what `scripts/make_test_docs.py` writes
into docs/evaluator/. The cases describe the static TUI as it is; rules only the Core API has
are listed in NOT_IN_STATIC, so nobody marks them as failures.
"""

from typing import Dict, Optional, Tuple

from . import cases_chat, cases_commands, cases_main, cases_setup, cases_web, results
from .model import MARKS, Case, Flow, Result

NOT_IN_STATIC = (
    "HIGH asks you to type the target (the static TUI uses a second Yes / No confirmation)",
    "Approvals expire after 30 minutes and are single use (Core API)",
    "A scope max_risk blocks a higher risk with BLOCKED / HTTP 422 (Core API)",
    "A report needs a sign-off before it can be downloaded (Core API)",
    "Severities NONE and UNKNOWN (the static TUI shows CRITICAL, HIGH, MEDIUM, LOW)",
    "Dash ranges such as 10.0.0.1-10.0.0.20 (use CIDR, e.g. 10.0.0.0/27)",
    "The AI agent mode (/assess) and a real AI model (the mock gives prepared answers)",
)

_FLOWS: Tuple[Flow, ...] = (
    (cases_setup.FLOW,)
    + cases_main.FLOWS
    + cases_chat.FLOWS
    + (cases_commands.FLOW,)
    + cases_web.FLOWS
)


def list_flows() -> Tuple[Flow, ...]:
    return _FLOWS


def all_cases() -> Dict[str, Case]:
    return {case.id: case for flow in _FLOWS for case in flow.cases}


def find_case(case_id: str) -> Optional[Case]:
    return all_cases().get(case_id.strip().upper())


__all__ = [
    "MARKS",
    "NOT_IN_STATIC",
    "Case",
    "Flow",
    "Result",
    "all_cases",
    "find_case",
    "list_flows",
    "results",
]
