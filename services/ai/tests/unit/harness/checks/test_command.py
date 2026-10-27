import pytest

from reconix_ai.harness.checks.command import check_command
from reconix_ai.harness.checks.result import Decision


def reason(tool: str, target: str = "172.20.0.5", arguments: list[str] | None = None) -> str | None:
    outcome = check_command(tool, target, arguments or [])
    return None if outcome.decision == Decision.ALLOW else outcome.reason


@pytest.mark.parametrize("tool", ["NMAP", "NUCLEI", "ZAP", "SEMGREP", "GITLEAKS", "nmap"])
def test_the_five_tools_are_allowed(tool: str) -> None:
    assert reason(tool, arguments=["-sV", "-p", "80,443"]) is None


@pytest.mark.parametrize("tool", ["METASPLOIT", "RUN_COMMAND", "BASH", "", "nmap2"])
def test_other_tools_are_blocked(tool: str) -> None:
    assert reason(tool) == "UNKNOWN_TOOL"


@pytest.mark.parametrize("character", [";", "|", "&", "$", "`", "<", ">", "\n", "\r", "\x00"])
def test_shell_characters_in_arguments_are_blocked(character: str) -> None:
    assert reason("NMAP", arguments=["-p", f"80{character}id"]) == "SHELL_CHARACTERS"


@pytest.mark.parametrize("target", ["172.20.0.5; id", "$(id)", "a`id`", "x && y", "x > /etc/x"])
def test_shell_characters_in_target_are_blocked(target: str) -> None:
    assert reason("NMAP", target=target) == "SHELL_CHARACTERS"


def test_one_string_instead_of_a_list_is_blocked() -> None:
    outcome = check_command("NMAP", "172.20.0.5", "-sV -p 80")
    assert outcome.reason == "ARGUMENTS_NOT_A_LIST"


def test_normal_values_are_allowed() -> None:
    arguments = ["-severity", "medium,high", "-tags", "cve", "--config", "p/default"]
    assert reason("NUCLEI", target="http://juice-shop.lab:3000/?a=1", arguments=arguments) is None
