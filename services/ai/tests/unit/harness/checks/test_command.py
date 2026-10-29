import pytest

from reconix_ai.harness.checks.command import ALLOWED_OPTIONS, check_command
from reconix_ai.harness.checks.result import Decision
from reconix_ai.harness.checks.risk import RISK_RULES


def reason(tool: str, target: str = "172.20.0.5", arguments: list[str] | None = None) -> str | None:
    outcome = check_command(tool, target, arguments or [])
    return None if outcome.decision == Decision.ALLOW else outcome.reason


@pytest.mark.parametrize("tool", ["NMAP", "NUCLEI", "ZAP", "SEMGREP", "GITLEAKS", "nmap"])
def test_the_five_tools_are_allowed(tool: str) -> None:
    assert reason(tool) is None


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
    arguments = ["-severity", "medium,high", "-tags", "cve"]
    assert reason("NUCLEI", target="http://juice-shop.lab:3000/?a=1", arguments=arguments) is None


# --- option allowlist ------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("NMAP", []),
        ("NMAP", ["-sV", "-Pn", "-T3", "-p", "22,80,443,8000-8100"]),
        ("NMAP", ["--top-ports", "100", "--script", "vuln,http-title"]),
        ("NMAP", ["-p", "0-65535"]),
        ("NUCLEI", ["-tags", "cve,xss", "-rate-limit", "150"]),
        ("NUCLEI", ["-rate-limit", "1", "-retries", "0", "-timeout", "60"]),
        ("NMAP", ["--top-ports", "65535"]),
        ("NMAP", ["--script=default"]),
        ("NUCLEI", ["-severity", "critical", "-rate-limit", "50", "-exclude-tags", "dos"]),
        ("ZAP", []),
        ("SEMGREP", ["--config", "p/owasp-top-ten"]),
        ("SEMGREP", ["--config=auto"]),
        ("GITLEAKS", ["--log-opts", "main..HEAD"]),
    ],
)
def test_allowed_options_and_values_pass(tool: str, arguments: list[str]) -> None:
    assert reason(tool, arguments=arguments) is None


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        # an extra target hidden in the arguments
        ("NMAP", ["-sV", "10.0.0.5"]),
        ("NMAP", ["169.254.169.254"]),
        ("SEMGREP", ["--config", "auto", "/etc"]),
        # options that read targets, write files or resume from a file
        ("NMAP", ["-iL", "/etc/passwd"]),
        ("NMAP", ["-iR", "100"]),
        ("NMAP", ["-oN", "/etc/cron.d/x"]),
        ("NMAP", ["-oN/etc/cron.d/x"]),
        ("NMAP", ["--resume", "/var/evil/x"]),
        ("NMAP", ["--script-args", "newtargets"]),
        ("NUCLEI", ["-u", "http://evil.com"]),
        ("NUCLEI", ["-l", "/var/evil/targets"]),
        ("NUCLEI", ["-t", "/var/evil/evil.yaml"]),
        ("SEMGREP", ["--output", "/root/x"]),
        ("GITLEAKS", ["--report-path", "/root/x"]),
        ("ZAP", ["-cmd"]),
        # a look-alike dash or a joined value
        ("NMAP", ["\u2010p", "80"]),
        ("NMAP", ["-p80"]),
        # another tool's option
        ("NMAP", ["-severity", "high"]),
    ],
)
def test_options_outside_the_allowlist_are_blocked(tool: str, arguments: list[str]) -> None:
    assert reason(tool, arguments=arguments) == "OPTION_NOT_ALLOWED"


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("NMAP", ["-p"]),
        ("NMAP", ["-p", "80,abc"]),
        ("NMAP", ["-p", "-sV"]),
        ("NMAP", ["-sV=1"]),
        ("NMAP", ["--top-ports", "1e9"]),
        # scripts load by name only: no path, no broadcast or target-adding scripts
        ("NMAP", ["--script", "/var/evil/evil.nse"]),
        ("NMAP", ["--script=../../var/evil"]),
        ("NMAP", ["--script", "broadcast-dhcp-discover"]),
        ("NMAP", ["--script", "vuln,targets-asn"]),
        ("NMAP", ["--script", "all"]),
        ("NUCLEI", ["-severity", "everything"]),
        # ports above 65535 do not exist
        ("NMAP", ["-p", "65536"]),
        ("NMAP", ["-p", "80,1-99999"]),
        ("NMAP", ["-p=99999"]),
        # denial-of-service templates and request floods
        ("NUCLEI", ["-tags", "dos"]),
        ("NUCLEI", ["-tags=cve,dos"]),
        ("NUCLEI", ["-tags", "fuzz"]),
        ("NUCLEI", ["-tags", "cve,fuzzing"]),
        ("NUCLEI", ["-rate-limit", "151"]),
        ("NUCLEI", ["-rate-limit=99999"]),
        # nuclei reads a rate limit of 0 as "no limit"
        ("NUCLEI", ["-rate-limit", "0"]),
        ("NUCLEI", ["-rate-limit", "00000"]),
        ("NUCLEI", ["-rate-limit", "100", "-rate-limit", "0"]),
        ("NUCLEI", ["-retries", "6"]),
        ("NUCLEI", ["-timeout", "0"]),
        ("NUCLEI", ["-timeout", "61"]),
        ("NMAP", ["--top-ports", "0"]),
        ("NMAP", ["--top-ports", "99999"]),
        ("SEMGREP", ["--config", "https://evil.example/r.yml"]),
        ("SEMGREP", ["--config", "/repos/app/rules.yml"]),
        ("GITLEAKS", ["--log-opts=--all --output=/root/.bashrc"]),
        ("GITLEAKS", ["--log-opts", "--ext-diff"]),
    ],
)
def test_bad_option_values_are_blocked(tool: str, arguments: list[str]) -> None:
    assert reason(tool, arguments=arguments) == "OPTION_VALUE_NOT_ALLOWED"


def test_allowlist_and_risk_table_list_the_same_options() -> None:
    for tool, options in ALLOWED_OPTIONS.items():
        assert set(options) == set(RISK_RULES[tool].options), tool
