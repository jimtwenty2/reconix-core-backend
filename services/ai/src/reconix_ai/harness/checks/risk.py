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
    raw, words = argument_texts(arguments)
    matched = [
        level
        for level, patterns in escalations(tool).items()
        for pattern in patterns
        if pattern in raw or " " + " ".join(pattern.replace("=", " ").split()) + " " in words
    ]
    return highest([base, *matched])


def argument_texts(arguments: Sequence[str]) -> tuple[str, str]:
    """Two lowercased texts the risk patterns are matched against, each with a space at both
    ends so a pattern like "-a " also matches a last "-A":

    - raw: the arguments joined with spaces, as written;
    - words: "--opt=a,b" and "--opt a,b" both written as "--opt a --opt b", so a pattern
      like "--script exploit" matches "--script=safe,exploit" too."""
    parts = [str(argument).lower() for argument in arguments]
    words: list[str] = []
    index = 0
    while index < len(parts):
        option, equals, value = parts[index].partition("=")
        if not equals and option.startswith("-") and index + 1 < len(parts):
            following = parts[index + 1]
            if not following.startswith("-"):
                value, equals = following, "="
                index += 1
        if equals and option.startswith("-"):
            words.extend(f"{option} {piece}" for piece in value.split(",") if piece)
        else:
            words.append(parts[index])
        index += 1
    return " " + " ".join(parts) + " ", " " + " ".join(words) + " "


def highest(levels: Sequence[RiskLevel]) -> RiskLevel:
    return max(levels, key=lambda level: RISK_ORDER[level])
