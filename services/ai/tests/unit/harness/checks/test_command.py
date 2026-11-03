import pytest

from reconix_ai.harness.checks.command import check_command
from reconix_ai.harness.checks.result import Decision


def reason(tool: str, target: str = "172.20.0.5", arguments: list[str] | None = None) -> str | None:
    outcome = check_command(tool, target, arguments or [])
    return None if outcome.decision == Decision.ALLOW else outcome.reason


# --- only tools with a rule run --------------------------------------------


@pytest.mark.parametrize(
    "tool",
    ["NMAP", "NUCLEI", "ZAP", "SEMGREP", "GITLEAKS", "nmap", "sqlmap", "masscan", "whatweb"],
)
def test_tools_with_a_rule_are_allowed(tool: str) -> None:
    assert reason(tool) is None


@pytest.mark.parametrize(
    "tool",
    ["run_command", "proxychains", "msfconsole", "smbclient", "impacket", "zap_start", "nikto"],
)
def test_catalog_tools_without_a_rule_are_not_supported(tool: str) -> None:
    assert reason(tool) == "TOOL_NOT_SUPPORTED"


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


def test_one_string_instead_of_a_list_is_blocked() -> None:
    outcome = check_command("NMAP", "172.20.0.5", "-sV -p 80")
    assert outcome.reason == "ARGUMENTS_NOT_A_LIST"


def test_normal_values_are_allowed() -> None:
    arguments = ["-severity", "medium,high", "-tags", "cve"]
    assert reason("NUCLEI", target="http://juice-shop.lab:3000/?a=1", arguments=arguments) is None


def test_listed_options_are_allowed() -> None:
    assert reason("NMAP", arguments=["-sV", "-Pn", "-p", "22,80", "--script", "vuln"]) is None
    assert reason("NMAP", arguments=["--top-ports=100"]) is None
    assert reason("WPSCAN", arguments=["-e", "vp,u1-5", "--plugins-detection=mixed"]) is None
    assert reason("DNSRECON", arguments=["-t", "std,srv"]) is None
    assert reason("SEMGREP", arguments=["--exclude", "tests/*", "--severity", "ERROR"]) is None


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("NMAP", ["-oN", "scan.out"]),  # not listed
        ("NMAP", ["-sV", "8.8.8.8"]),  # a second target as a bare word
        ("NMAP", ["-iL", "hosts.txt"]),  # a file of targets
        ("WPSCAN", ["-e", "--url=169.254.169.254"]),  # a value never starts with "-"
        ("WPSCAN", ["--proxy", "evil:8080"]),
        ("NMAP", ["--script", "/workspace/code/s1/evil.nse"]),  # a script file
        ("NMAP", ["--script", "evil.nse"]),
        ("NMAP", ["--script=safe,exploit"]),  # a blocked category
        ("NMAP", ["--script", "broadcast"]),
        ("DNSRECON", ["-t", "tld"]),  # every TLD: domains outside the scope
        ("DNSRECON", ["-t", "crt,axfr"]),
        ("SQLMAP", ["--level", "9"]),
        ("SEMGREP", ["--include", "../../etc/*"]),
        ("WHATWEB", ["http://169.254.169.254/"]),
        ("SQLMAP", ["-u", "http://evil.example/"]),
        ("NUCLEI", ["-severity"]),  # an option missing its value
        ("MASSCAN", ["--rate", "100000"]),  # takes no options at all
        ("ZAP", ["-x"]),
    ],
)
def test_other_options_and_bare_words_are_blocked(tool: str, arguments: list[str]) -> None:
    assert reason(tool, target="http://172.20.0.5/", arguments=arguments) == "OPTION_NOT_ALLOWED"
