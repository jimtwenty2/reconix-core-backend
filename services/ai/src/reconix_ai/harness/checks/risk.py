"""Risk check: the fourth of the 5 checks.

A call's risk starts at the tool's baseline (the "risk" field in tool_specs.json),
and a destructive or free-shell tool is pushed to at least HIGH. risk_ops.json
then raises a single call above that baseline when one of the tool's escalation
patterns is a substring of the (lowercased, space-joined) argument values. A tool
the catalog does not know counts as HIGH, and validating a finding (a PoC) is at
least MEDIUM. An action above the scope's max risk is blocked; otherwise the risk
decides what happens next: LOW runs right away, MEDIUM and HIGH wait for a person.
"""

from collections.abc import Sequence

from reconix_ai.harness.catalog import (
    baseline_risk,
    escalations,
    is_destructive,
    is_free_shell,
)
from reconix_ai.harness.checks.result import (
    RISK_ORDER,
    CheckOutcome,
    Decision,
    RiskLevel,
    blocked,
)

LOW, MEDIUM, HIGH = RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH


def check_risk(
    tool: str,
    arguments: Sequence[str],
    is_validation: bool,
    max_risk: RiskLevel,
) -> CheckOutcome:
    risk = action_risk(tool, arguments)
    if is_validation:
        risk = highest([risk, MEDIUM])
    if RISK_ORDER[risk] > RISK_ORDER[RiskLevel(max_risk)]:
        return blocked("RISK_ABOVE_SCOPE_MAX", risk)
    return CheckOutcome(decision=Decision.ALLOW, risk=risk)


def action_risk(tool: str, arguments: Sequence[str]) -> RiskLevel:
    base = baseline_risk(tool)
    if is_destructive(tool) or is_free_shell(tool):
        base = highest([base, HIGH])
    joined = " ".join(str(argument) for argument in arguments).lower()
    matched = [
        level
        for level, patterns in escalations(tool).items()
        for pattern in patterns
        if pattern in joined
    ]
    return highest([base, *matched])


def highest(levels: Sequence[RiskLevel]) -> RiskLevel:
    return max(levels, key=lambda level: RISK_ORDER[level])
