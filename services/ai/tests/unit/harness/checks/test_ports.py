"""The port part of the scope check: with allowed ports, nmap scans only those."""

from dataclasses import dataclass, field

import pytest

from reconix_ai.harness.checks.result import Decision
from reconix_ai.harness.checks.scope import check_ports, port_set


@dataclass(frozen=True)
class Scope:
    allowed_ports: list[int] = field(default_factory=lambda: [22, 80, 443, 8000, 8001, 8002])


SCOPE = Scope()


def reason(arguments: list[str], tool: str = "NMAP", scope: object = SCOPE) -> str | None:
    outcome = check_ports(tool, arguments, scope)
    return None if outcome.decision == Decision.ALLOW else outcome.reason


@pytest.mark.parametrize(
    "arguments",
    [
        ["-sV", "-p", "22,80,443"],
        ["-p", "8000-8002"],
        ["-p", "22", "-sV", "-p", "443"],
    ],
)
def test_ports_inside_the_list_are_allowed(arguments) -> None:
    assert reason(arguments) is None


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (["-sV"], "PORTS_NOT_GIVEN"),  # nmap would pick its own top 1000
        (["-p", "3389"], "PORTS_OUT_OF_SCOPE"),
        (["-p", "22,3389"], "PORTS_OUT_OF_SCOPE"),
        (["-p", "7999-8002"], "PORTS_OUT_OF_SCOPE"),
        (["-p", "22", "--top-ports", "100"], "PORTS_OUT_OF_SCOPE"),
        (["-p", "22", "--top-ports=100"], "PORTS_OUT_OF_SCOPE"),
        (["-p", "22", "-F"], "PORTS_OUT_OF_SCOPE"),
        (["-p-"], "PORTS_OUT_OF_SCOPE"),
        (["-p22"], "BAD_PORTS"),
        (["-p"], "BAD_PORTS"),
        (["-p", "T:22"], "BAD_PORTS"),
        (["-p", "0"], "BAD_PORTS"),
        (["-p", "70000"], "BAD_PORTS"),
        (["-p", "443-80"], "BAD_PORTS"),
    ],
)
def test_other_ports_are_blocked(arguments, code) -> None:
    assert reason(arguments) == code


def test_no_allowed_ports_means_no_limit() -> None:
    assert reason(["--top-ports", "1000"], scope=Scope(allowed_ports=[])) is None


def test_a_scope_without_the_field_puts_no_limit() -> None:
    assert reason(["--top-ports", "1000"], scope=object()) is None


def test_other_tools_take_their_port_from_the_target() -> None:
    assert reason(["-severity", "high"], tool="NUCLEI") is None


def test_a_port_list_reads_as_a_set() -> None:
    assert port_set("22,80-82") == {22, 80, 81, 82}
    assert port_set("22,,80") is None
