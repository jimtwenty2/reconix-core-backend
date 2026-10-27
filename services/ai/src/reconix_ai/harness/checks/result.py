"""The result every check returns.

The harness does not import reconix_api, so it keeps its own small result.
The pipeline turns it into a PipelineResult, which has the same fields as the
shared CheckResult in core/interfaces.py.
"""

from dataclasses import dataclass
from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCKED = "BLOCKED"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


RISK_ORDER = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}


@dataclass(frozen=True)
class CheckOutcome:
    decision: Decision
    reason: str | None = None  # short UPPERCASE code, e.g. "INPUT_TOO_LONG"
    risk: RiskLevel | None = None  # only the risk check sets it


ALLOWED = CheckOutcome(decision=Decision.ALLOW)


def blocked(reason: str, risk: RiskLevel | None = None) -> CheckOutcome:
    return CheckOutcome(decision=Decision.BLOCKED, reason=reason, risk=risk)
