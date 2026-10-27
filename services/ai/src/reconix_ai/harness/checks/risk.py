"""Risk check: the fourth of the 5 checks.

A rule table gives each tool a base level and each option its own level. The
action's risk is the highest of them. Anything the table does not know counts
as HIGH, and validating a finding (a PoC) is at least MEDIUM. An action above
the scope's max risk is blocked; otherwise the risk decides what happens next:
LOW runs right away, MEDIUM and HIGH wait for a person to approve.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from reconix_ai.harness.checks.result import (
    RISK_ORDER,
    CheckOutcome,
    Decision,
    RiskLevel,
    blocked,
)

LOW, MEDIUM, HIGH = RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH


@dataclass(frozen=True)
class ToolRisk:
    base: RiskLevel
    options: dict[str, RiskLevel] = field(default_factory=dict)


# Base levels follow the "risk" in tool_specs.json from Reconix-Kali-MCP.
# Draft: the option rows will be tuned once tool_specs.json lists the allowed
# options, and again with real runs on the lab (week 2).
RISK_RULES: dict[str, ToolRisk] = {
    "NMAP": ToolRisk(
        base=MEDIUM,
        options={
            "-p": LOW,
            "--top-ports": LOW,
            "-F": LOW,
            "-Pn": LOW,
            "-n": LOW,
            "-sT": LOW,
            "-sS": LOW,
            "-sV": LOW,
            "-sC": MEDIUM,
            "-sU": MEDIUM,
            "-O": MEDIUM,
            "-A": MEDIUM,
            "-T0": LOW,
            "-T1": LOW,
            "-T2": LOW,
            "-T3": LOW,
            "-T4": MEDIUM,
            "-T5": HIGH,
            "--script": HIGH,
            "--script-args": HIGH,
        },
    ),
    "NUCLEI": ToolRisk(
        base=MEDIUM,
        options={
            "-severity": LOW,
            "-tags": LOW,
            "-exclude-tags": LOW,
            "-rate-limit": LOW,
            "-timeout": LOW,
            "-retries": LOW,
        },
    ),
    "ZAP": ToolRisk(base=HIGH),  # active scan sends attack requests
    "SEMGREP": ToolRisk(base=LOW, options={"--config": LOW}),
    "GITLEAKS": ToolRisk(base=LOW, options={"--log-opts": LOW}),
}


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
    rules = RISK_RULES.get(tool.upper())
    if rules is None:
        return HIGH
    levels = [rules.base]
    for argument in arguments:
        if argument.startswith("-"):
            # "--script=vuln" is the same option as "--script vuln".
            option = argument.split("=", 1)[0]
            levels.append(rules.options.get(option, HIGH))
    return highest(levels)


def highest(levels: Sequence[RiskLevel]) -> RiskLevel:
    return max(levels, key=lambda level: RISK_ORDER[level])
