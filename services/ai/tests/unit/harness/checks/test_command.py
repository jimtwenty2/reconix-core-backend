import pytest

from reconix_ai.harness.checks.command import check_command
from reconix_ai.harness.checks.result import Decision


def reason(tool: str, target: str = "172.20.0.5", arguments: list[str] | None = None) -> str | None:
    outcome = check_command(tool, target, arguments or [])
    return None if outcome.decision == Decision.ALLOW else outcome.reason


# --- the catalog decides which tools are known -----------------------------


@pytest.mark.parametrize(
    "tool",
    ["NMAP", "NUCLEI", "ZAP", "SEMGREP", "GITLEAKS", "nmap", "sqlmap", "masscan", "whatweb"],
)
def test_catalog_tools_are_allowed(tool: str) -> None:
    assert reason(tool) is None


@pytest.mark.parametrize("tool", ["METASPLOIT", "BASH", "", "nmap2", "nessus"])
def test_tools_outside_the_catalog_are_blocked(tool: str) -> None:
    assert reason(tool) == "UNKNOWN_TOOL"


# --- shell characters are blocked (except for the free-shell tools) --------


@pytest.mark.parametrize("character", [";", "|", "&", "$", "`", "<", ">", "\n", "\r", "\x00"])
def test_shell_characters_in_arguments_are_blocked(character: str) -> None:
    assert reason("NMAP", arguments=["-p", f"80{character}id"]) == "SHELL_CHARACTERS"


@pytest.mark.parametrize("target", ["172.20.0.5; id", "$(id)", "a`id`", "x && y", "x > /etc/x"])
def test_shell_characters_in_target_are_blocked(target: str) -> None:
    assert reason("NMAP", target=target) == "SHELL_CHARACTERS"


@pytest.mark.parametrize("tool", ["run_command", "proxychains", "msfconsole", "smbclient"])
def test_free_shell_tools_allow_shell_characters(tool: str) -> None:
    # Their input is a real shell command; the risk check pins them to HIGH instead.
    assert reason(tool, target="nmap -sV x | tee out && id") is None


def test_one_string_instead_of_a_list_is_blocked() -> None:
    outcome = check_command("NMAP", "172.20.0.5", "-sV -p 80")
    assert outcome.reason == "ARGUMENTS_NOT_A_LIST"


def test_normal_values_are_allowed() -> None:
    arguments = ["-severity", "medium,high", "-tags", "cve"]
    assert reason("NUCLEI", target="http://juice-shop.lab:3000/?a=1", arguments=arguments) is None


def test_options_are_no_longer_flag_allowlisted() -> None:
    # The per-flag allowlist is gone: the command check only blocks shell characters
    # and unknown tools. A risky flag is rated by the risk check and sent for approval
    # (and the Kali container is sandboxed), not refused here.
    assert reason("NMAP", arguments=["-oN", "scan.out"]) is None
    assert reason("NMAP", arguments=["--script", "vuln"]) is None
