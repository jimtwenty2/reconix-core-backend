"""Hosts, IPs and URLs written in option values must be inside the scope too."""

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

import pytest

from reconix_ai.harness.checks.result import Decision
from reconix_ai.harness.checks.scope import check_argument_targets, check_scope


@dataclass(frozen=True)
class Scope:
    ip_ranges: list[str] = field(default_factory=lambda: ["172.20.0.0/24", "169.254.0.0/16"])
    domains: list[str] = field(default_factory=lambda: ["juice-shop.lab"])
    url_prefixes: list[str] = field(default_factory=lambda: ["http://172.20.0.5:8000/"])
    repo_paths: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=lambda: ["http://172.20.0.5:8000/admin"])
    allowed_tools: list[str] = field(default_factory=lambda: ["NMAP", "NUCLEI", "SEMGREP"])
    allowed_ports: list[int] = field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None


SCOPE = Scope()


def reason(tool: str, arguments: list[str], scope: Scope = SCOPE) -> str | None:
    outcome = check_argument_targets(tool, arguments, scope)
    return None if outcome.decision == Decision.ALLOW else outcome.reason


@pytest.mark.parametrize(
    "arguments",
    [
        ["-sV", "-p", "22,80", "--script", "http-title"],
        ["-T4", "--top-ports=100"],
    ],
)
def test_values_that_name_no_host_are_allowed(arguments: list[str]) -> None:
    assert reason("NMAP", arguments) is None


# Most option values cannot hold a host at all (their patterns refuse dots and colons).
# A glob value can, so it is what reaches this second check.


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ("8.8.8.8", "TARGET_OUT_OF_SCOPE"),
        ("evil.example", "TARGET_OUT_OF_SCOPE"),
        ("juice-shop.lab", None),
        ("172.20.0.9", None),
        ("src/*.py", None),
    ],
)
def test_hosts_in_values_must_be_in_scope(value: str, code: str | None) -> None:
    assert reason("SEMGREP", ["--include", value]) == code


def test_a_host_in_a_value_is_blocked_when_ports_are_limited() -> None:
    scope = replace(SCOPE, allowed_ports=[8000])
    assert reason("SEMGREP", ["--include=172.20.0.5"], scope) == "PORTS_NOT_SUPPORTED"


@pytest.mark.parametrize(
    "target",
    ["169.254.169.254", "http://169.254.169.254/latest/", "metadata.google.internal"],
)
def test_metadata_addresses_are_never_a_target(target: str) -> None:
    # Even when a scope range or domain covers them.
    prefixes = ["http://169.254.169.254/"]
    scope = replace(SCOPE, domains=["metadata.google.internal"], url_prefixes=prefixes)
    outcome = check_scope("NUCLEI" if "://" in target else "NMAP", target, scope, datetime.now(UTC))
    assert outcome.reason == "TARGET_NOT_ALLOWED"


def test_a_metadata_address_in_a_value_is_blocked() -> None:
    assert reason("SEMGREP", ["--include", "169.254.169.254"]) == "TARGET_NOT_ALLOWED"


def test_a_catalog_tool_without_a_rule_is_not_supported() -> None:
    scope = replace(SCOPE, allowed_tools=["RUN_COMMAND"])
    outcome = check_scope("run_command", "172.20.0.5", scope, datetime.now(UTC))
    assert outcome.reason == "TOOL_NOT_SUPPORTED"
