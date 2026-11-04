"""The port part of the scope check: with allowed ports, a tool reaches only those."""

from dataclasses import dataclass, field

import pytest

from reconix_ai.harness.checks.result import Decision
from reconix_ai.harness.checks.scope import check_ports, port_set


@dataclass(frozen=True)
class Scope:
    allowed_ports: list[int] = field(default_factory=lambda: [22, 80, 443, 8000, 8001, 8002])


SCOPE = Scope()
HOST = "172.20.0.5"


def reason(
    arguments: list[str], tool: str = "NMAP", scope: object = SCOPE, target: str = HOST
) -> str | None:
    outcome = check_ports(tool, target, arguments, scope)
    return None if outcome.decision == Decision.ALLOW else outcome.reason


@pytest.mark.parametrize(
    "arguments",
    [
        ["-Pn", "-sV", "-p", "22,80,443"],
        ["-Pn", "-p", "8000-8002"],
        ["-p", "22", "-sV", "-Pn", "-p", "443"],
    ],
)
def test_ports_inside_the_list_are_allowed(arguments) -> None:
    assert reason(arguments) is None


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (["-Pn", "-sV"], "PORTS_NOT_GIVEN"),  # nmap would pick its own top 1000
        (["-Pn", "-p", "3389"], "PORTS_OUT_OF_SCOPE"),
        (["-Pn", "-p", "22,3389"], "PORTS_OUT_OF_SCOPE"),
        (["-Pn", "-p", "7999-8002"], "PORTS_OUT_OF_SCOPE"),
        (["-Pn", "-p", "22", "--top-ports", "100"], "PORTS_OUT_OF_SCOPE"),
        (["-Pn", "-p", "22", "--top-ports=100"], "PORTS_OUT_OF_SCOPE"),
        (["-Pn", "-p", "22", "-F"], "PORTS_OUT_OF_SCOPE"),
        (["-Pn", "-p-"], "PORTS_OUT_OF_SCOPE"),
        (["-Pn", "-p22"], "BAD_PORTS"),
        (["-Pn", "-p"], "BAD_PORTS"),
        (["-Pn", "-p", "T:22"], "BAD_PORTS"),
        (["-Pn", "-p", "0"], "BAD_PORTS"),
        (["-Pn", "-p", "70000"], "BAD_PORTS"),
        (["-Pn", "-p", "443-80"], "BAD_PORTS"),
    ],
)
def test_other_ports_are_blocked(arguments, code) -> None:
    assert reason(arguments) == code


@pytest.mark.parametrize("option", ["-O", "-A", "-sC", "--script"])
def test_options_that_probe_other_ports_are_blocked(option) -> None:
    arguments = ["-Pn", "-p", "22", option]
    if option == "--script":
        arguments.append("smb-os-discovery")
    assert reason(arguments) == "PORTS_OUT_OF_SCOPE"


def test_nmap_needs_no_host_discovery() -> None:
    # Without -Pn, nmap's own ping probes 80 and 443 whatever -p says.
    assert reason(["-p", "22"]) == "HOST_DISCOVERY_NOT_ALLOWED"


def test_no_allowed_ports_means_no_limit() -> None:
    assert reason(["--top-ports", "1000"], scope=Scope(allowed_ports=[])) is None


@pytest.mark.parametrize(
    ("tool", "target", "code"),
    [
        ("NUCLEI", "http://172.20.0.5/", None),  # 80 from the scheme
        ("NUCLEI", "https://172.20.0.5:8001/app", None),
        ("ZAP", "http://172.20.0.5:3000/", "PORTS_OUT_OF_SCOPE"),
        ("ZAP", "https://172.20.0.5:99999/", "BAD_PORTS"),
        ("NUCLEI", "lab.example.test", "PORTS_NOT_GIVEN"),  # nuclei would pick its own
    ],
)
def test_web_tools_take_their_port_from_the_url(tool, target, code) -> None:
    assert reason(["-severity", "high"], tool=tool, target=target) == code


def test_source_tools_have_no_ports() -> None:
    assert reason([], tool="SEMGREP", target="/repos/app") is None


def test_a_port_list_reads_as_a_set() -> None:
    assert port_set("22,80-82") == {22, 80, 81, 82}
    assert port_set("22,,80") is None


@pytest.mark.parametrize("tool", ["MASSCAN", "RUSTSCAN", "NETCAT", "HYDRA", "masscan"])
def test_other_tools_on_a_host_are_blocked_when_ports_are_limited(tool: str) -> None:
    # They pick their own ports (masscan scans all of them) and Core cannot limit them.
    assert reason(["-p", "1-65535"], tool=tool) == "PORTS_NOT_SUPPORTED"


def test_other_tools_on_a_host_are_allowed_without_a_port_limit() -> None:
    assert reason([], tool="MASSCAN", scope=Scope(allowed_ports=[])) is None


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("http://172.20.0.5:8000/", None),
        ("https://172.20.0.5/", None),
        ("http://172.20.0.5:9999/", "PORTS_OUT_OF_SCOPE"),
    ],
)
def test_other_tools_on_a_url_reach_only_its_allowed_port(target: str, code: str | None) -> None:
    assert reason([], tool="SQLMAP", target=target) == code


def test_other_tools_on_a_path_reach_no_port() -> None:
    assert reason([], tool="TRIVY", target="/lab/vuln-repo") is None


def test_zap_scan_is_checked_like_zap() -> None:
    assert reason([], tool="zap_scan", target="http://172.20.0.5:9999/") == "PORTS_OUT_OF_SCOPE"
