import pytest

from reconix_ai.harness.checks.result import Decision, RiskLevel
from reconix_ai.harness.checks.risk import check_risk

LOW, MEDIUM, HIGH = RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH


def risk_of(tool: str, arguments: list[str], is_validation: bool = False) -> RiskLevel:
    """The risk of an action when the scope allows everything up to HIGH."""
    outcome = check_risk(tool, arguments, is_validation, max_risk=HIGH)
    assert outcome.decision == Decision.ALLOW
    return outcome.risk


# --- base level per tool ---------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("NMAP", MEDIUM),
        ("NUCLEI", MEDIUM),
        ("ZAP", HIGH),
        ("SEMGREP", LOW),
        ("GITLEAKS", LOW),
    ],
)
def test_each_tool_has_a_base_level(tool: str, expected: RiskLevel) -> None:
    assert risk_of(tool, []) == expected


def test_tool_name_case_does_not_matter() -> None:
    assert risk_of("semgrep", []) == LOW


def test_unknown_tool_is_high() -> None:
    assert risk_of("METASPLOIT", []) == HIGH


# --- options ---------------------------------------------------------------


def test_safe_options_keep_the_base_level() -> None:
    assert risk_of("NMAP", ["-sV", "-p", "80,443", "-Pn"]) == MEDIUM


def test_risky_option_raises_the_level() -> None:
    assert risk_of("NMAP", ["-sV", "--script", "vuln"]) == HIGH
    assert risk_of("NMAP", ["-T5"]) == HIGH


def test_option_with_equals_is_the_same_option() -> None:
    assert risk_of("NMAP", ["--script=vuln"]) == HIGH
    assert risk_of("SEMGREP", ["--config=p/default"]) == LOW


@pytest.mark.parametrize("option", ["-oN", "--unknown", "-p80", "--SCRIPT"])
def test_unknown_option_is_high(option: str) -> None:
    assert risk_of("NMAP", [option]) == HIGH


def test_unknown_option_on_a_low_tool_is_high() -> None:
    assert risk_of("GITLEAKS", ["--no-git"]) == HIGH


def test_values_are_not_treated_as_options() -> None:
    assert risk_of("SEMGREP", ["--config", "p/default"]) == LOW


# --- validating a finding --------------------------------------------------


def test_validation_is_at_least_medium() -> None:
    assert risk_of("SEMGREP", [], is_validation=True) == MEDIUM


def test_validation_does_not_lower_a_high_action() -> None:
    assert risk_of("ZAP", [], is_validation=True) == HIGH


# --- the scope's max risk --------------------------------------------------


def test_risk_at_the_scope_max_is_allowed() -> None:
    outcome = check_risk("NMAP", ["-sV"], is_validation=False, max_risk=MEDIUM)
    assert outcome.decision == Decision.ALLOW
    assert outcome.risk == MEDIUM


def test_risk_above_the_scope_max_is_blocked() -> None:
    outcome = check_risk("NMAP", ["--script", "vuln"], is_validation=False, max_risk=MEDIUM)
    assert outcome.decision == Decision.BLOCKED
    assert outcome.reason == "RISK_ABOVE_SCOPE_MAX"
    assert outcome.risk == HIGH


def test_low_scope_only_allows_low_actions() -> None:
    assert check_risk("GITLEAKS", [], False, max_risk=LOW).decision == Decision.ALLOW
    assert check_risk("NMAP", [], False, max_risk=LOW).decision == Decision.BLOCKED
    assert check_risk("GITLEAKS", [], True, max_risk=LOW).decision == Decision.BLOCKED


def test_max_risk_can_be_a_plain_string() -> None:
    # The shared ApprovedScope uses its own RiskLevel enum; its values are the same strings.
    assert check_risk("NMAP", [], False, max_risk="MEDIUM").decision == Decision.ALLOW
