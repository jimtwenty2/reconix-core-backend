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
    allowed_tools: list[str] = field(default_factory=lambda: ["NMAP", "NUCLEI", "SQLMAP"])
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


@pytest.mark.parametrize(
    ("tool", "arguments", "code"),
    [
        ("NUCLEI", ["-id", "http://10.9.9.9/"], "TARGET_OUT_OF_SCOPE"),
        ("NUCLEI", ["-tags", "cve,evil.example"], "TARGET_OUT_OF_SCOPE"),
        ("NUCLEI", ["-tags=8.8.8.8"], "TARGET_OUT_OF_SCOPE"),
        ("NUCLEI", ["-id", "http://172.20.0.5:8000/admin"], "TARGET_EXCLUDED"),
        ("NMAP", ["--script", "juice-shop.lab:22"], None),
    ],
)
def test_hosts_in_values_must_be_in_scope(tool: str, arguments: list[str], code) -> None:
    assert reason(tool, arguments) == code


def test_a_url_in_a_value_must_use_an_allowed_port() -> None:
    prefixes = ["http://172.20.0.5:8000/", "http://172.20.0.5/"]  # 80 is in scope, not allowed
    scope = replace(SCOPE, allowed_ports=[8000], url_prefixes=prefixes)
    assert reason("NUCLEI", ["-id", "http://172.20.0.5:8000/x"], scope) is None
    assert reason("NUCLEI", ["-id", "http://172.20.0.5/"], scope) == "PORTS_OUT_OF_SCOPE"
    assert reason("NUCLEI", ["-id", "172.20.0.5"], scope) == "PORTS_NOT_SUPPORTED"


@pytest.mark.parametrize(
    "target",
    ["169.254.169.254", "http://169.254.169.254/latest/", "metadata.google.internal"],
)
def test_metadata_addresses_are_never_a_target(target: str) -> None:
    # Even when a scope range or domain covers them.
    scope = replace(
        SCOPE, domains=["metadata.google.internal"], url_prefixes=["http://169.254.169.254/"]
    )
    outcome = check_scope("NUCLEI" if "://" in target else "NMAP", target, scope, datetime.now(UTC))
    assert outcome.reason == "TARGET_NOT_ALLOWED"
    assert reason("NUCLEI", ["-id", target], scope) == "TARGET_NOT_ALLOWED"


def test_a_catalog_tool_without_a_rule_is_not_supported() -> None:
    scope = replace(SCOPE, allowed_tools=["RUN_COMMAND"])
    outcome = check_scope("run_command", "172.20.0.5", scope, datetime.now(UTC))
    assert outcome.reason == "TOOL_NOT_SUPPORTED"
