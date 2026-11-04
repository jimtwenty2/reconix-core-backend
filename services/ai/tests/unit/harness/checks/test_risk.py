import pytest

from reconix_ai.harness.checks.result import Decision, RiskLevel
from reconix_ai.harness.checks.risk import action_risk, check_risk

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
        ("NMAP", LOW),
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
    assert risk_of("NMAP", ["-sV", "-p", "80,443", "-Pn"]) == LOW


def test_risk_ops_pattern_raises_the_level() -> None:
    # risk_ops.json escalates nmap's offensive NSE categories to HIGH.
    assert risk_of("NMAP", ["--script=vuln"]) == HIGH
    # The bare "--script" pattern raises any scripted scan to at least MEDIUM.
    assert risk_of("NMAP", ["--script", "http-title"]) == MEDIUM
    assert risk_of("SEMGREP", ["--config=p/default"]) == LOW


def test_destructive_tool_is_at_least_high() -> None:
    # tool_specs marks these destructive; risk_ops does not escalate them, so the
    # destructive flag is what pins them to HIGH.
    assert risk_of("sqlmap", []) == HIGH
    assert risk_of("hydra", []) == HIGH


def test_free_shell_tool_is_at_least_high() -> None:
    assert risk_of("run_command", []) == HIGH


def test_unrecognized_option_uses_the_tool_baseline() -> None:
    # No per-flag allowlist any more: an option risk_ops does not name leaves the
    # call at the tool's baseline, not HIGH.
    assert risk_of("NMAP", ["-oN", "scan.out"]) == LOW
    assert risk_of("GITLEAKS", ["--no-git"]) == LOW


def test_values_are_not_treated_as_options() -> None:
    assert risk_of("SEMGREP", ["--config", "p/default"]) == LOW


# --- validating a finding --------------------------------------------------


def test_validation_is_at_least_medium() -> None:
    assert risk_of("SEMGREP", [], is_validation=True) == MEDIUM


def test_validation_does_not_lower_a_high_action() -> None:
    assert risk_of("ZAP", [], is_validation=True) == HIGH


# --- the scope's max risk --------------------------------------------------


def test_risk_at_the_scope_max_is_allowed() -> None:
    # -sU is a MEDIUM option, so the action lands exactly on the scope's max.
    outcome = check_risk("NMAP", ["-sU"], is_validation=False, max_risk=MEDIUM)
    assert outcome.decision == Decision.ALLOW
    assert outcome.risk == MEDIUM


def test_risk_above_the_scope_max_is_blocked() -> None:
    outcome = check_risk("NMAP", ["--script=vuln"], is_validation=False, max_risk=MEDIUM)
    assert outcome.decision == Decision.BLOCKED
    assert outcome.reason == "RISK_ABOVE_SCOPE_MAX"
    assert outcome.risk == HIGH


def test_low_scope_only_allows_low_actions() -> None:
    assert check_risk("GITLEAKS", [], False, max_risk=LOW).decision == Decision.ALLOW
    # NUCLEI's base is MEDIUM, so a LOW scope must refuse it.
    assert check_risk("NUCLEI", [], False, max_risk=LOW).decision == Decision.BLOCKED
    assert check_risk("GITLEAKS", [], True, max_risk=LOW).decision == Decision.BLOCKED


def test_max_risk_can_be_a_plain_string() -> None:
    # The shared ApprovedScope uses its own RiskLevel enum; its values are the same strings.
    assert check_risk("NMAP", [], False, max_risk="MEDIUM").decision == Decision.ALLOW


@pytest.mark.parametrize(
    "arguments",
    [["--script", "safe,exploit"], ["--script=dos"], ["--script", "vuln"], ["--script=brute"]],
)
def test_offensive_script_categories_are_high_in_any_form(arguments: list[str]) -> None:
    assert action_risk("NMAP", arguments) == RiskLevel.HIGH


@pytest.mark.parametrize("arguments", [["-A"], ["-O"], ["-Pn", "-A"], ["-sU"]])
def test_intrusive_nmap_options_are_medium_even_as_the_last_argument(arguments) -> None:
    assert action_risk("NMAP", arguments) == RiskLevel.MEDIUM
