import pytest

from reconix_ai.harness.catalog import canonical, is_known_tool, same_tool_names


@pytest.mark.parametrize("tool", ["ZAP", "zap", "zap_scan", "ZAP_SCAN"])
def test_zap_and_its_catalog_name_are_one_tool(tool: str) -> None:
    assert canonical(tool) == "zap_scan"
    assert same_tool_names(tool) == {"ZAP_SCAN", "ZAP"}


def test_a_tool_without_an_alias_has_one_name() -> None:
    assert same_tool_names("masscan") == {"MASSCAN"}


@pytest.mark.parametrize(("tool", "known"), [("MASSCAN", True), ("nmap", True), ("nope", False)])
def test_known_tools_come_from_the_catalog_in_any_case(tool: str, known: bool) -> None:
    assert is_known_tool(tool) is known
