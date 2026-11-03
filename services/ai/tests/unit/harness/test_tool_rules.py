import pytest

from reconix_ai.harness.catalog import input_schema, is_known_tool
from reconix_ai.harness.tool_rules import RULES, option_values, supported_tools


@pytest.mark.parametrize("name", sorted(RULES))
def test_every_rule_matches_the_kali_catalog(name: str) -> None:
    """The target goes in a real param, and options only where the tool takes opts."""
    rule = RULES[name]
    props = input_schema(name).get("properties", {})
    assert is_known_tool(name)
    assert rule.target_param in props
    if rule.flags or rule.valued:
        assert "opts" in props


def test_supported_tools_are_uppercase() -> None:
    assert "NMAP" in supported_tools()
    assert "ZAP_SCAN" in supported_tools()
    assert "RUN_COMMAND" not in supported_tools()


def test_option_values_reads_both_value_forms() -> None:
    assert option_values("nmap", ["-sV", "-p", "22", "--top-ports=10"]) == ["22", "10"]
    assert option_values("nmap", ["-p"]) is None  # a value is missing
    assert option_values("nmap", ["8.8.8.8"]) is None  # a bare word
    assert option_values("run_command", []) is None  # no rule
