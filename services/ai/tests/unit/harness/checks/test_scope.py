from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

import pytest

from reconix_ai.harness.checks.result import Decision
from reconix_ai.harness.checks.scope import check_scope

NOW = datetime(2026, 10, 26, 14, 0, tzinfo=UTC)
ALL_TOOLS = ["NMAP", "NUCLEI", "ZAP", "SEMGREP", "GITLEAKS"]


@dataclass(frozen=True)
class Scope:
    """Same fields as the shared ApprovedScope."""

    ip_ranges: list[str] = field(default_factory=lambda: ["172.20.0.0/24", "fd00:20::/64"])
    domains: list[str] = field(default_factory=lambda: ["juice-shop.lab", "*.reconix.lab"])
    url_prefixes: list[str] = field(
        default_factory=lambda: [
            "http://juice-shop.lab:3000/",
            "https://app.reconix.lab/api",
        ]
    )
    repo_paths: list[str] = field(default_factory=lambda: ["/lab/vuln-repo"])
    excluded_targets: list[str] = field(
        default_factory=lambda: [
            "172.20.0.1",
            "admin.reconix.lab",
            "http://juice-shop.lab:3000/admin",
            "/lab/vuln-repo/.git",
        ]
    )
    allowed_tools: list[str] = field(default_factory=lambda: list(ALL_TOOLS))
    window_start: datetime | None = None
    window_end: datetime | None = None


SCOPE = Scope()


def assert_allowed(target: str, tool: str = "NMAP", scope: Scope = SCOPE) -> None:
    outcome = check_scope(tool, target, scope, NOW)
    assert outcome.decision == Decision.ALLOW, outcome.reason


def assert_blocked(target: str, reason: str, tool: str = "NMAP", scope: Scope = SCOPE) -> None:
    outcome = check_scope(tool, target, scope, NOW)
    assert outcome.decision == Decision.BLOCKED
    assert outcome.reason == reason


# --- IPs and networks ------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["172.20.0.5", "172.20.0.254", "172.20.0.16/28", "fd00:20::5", "[fd00:20::5]"],
)
def test_ip_in_range_is_allowed(target: str) -> None:
    assert_allowed(target)


@pytest.mark.parametrize(
    "target",
    ["172.20.1.5", "8.8.8.8", "10.0.0.1", "fd00:21::5", "::1"],
)
def test_ip_outside_range_is_blocked(target: str) -> None:
    assert_blocked(target, "TARGET_OUT_OF_SCOPE")


def test_ipv4_written_as_ipv6_is_treated_as_ipv4() -> None:
    assert_allowed("::ffff:172.20.0.5")
    assert_blocked("::ffff:8.8.8.8", "TARGET_OUT_OF_SCOPE")
    assert_blocked("::ffff:172.20.0.1", "TARGET_EXCLUDED")


def test_excluded_ip_is_blocked_even_inside_the_range() -> None:
    assert_blocked("172.20.0.1", "TARGET_EXCLUDED")


def test_network_bigger_than_the_range_is_blocked() -> None:
    no_exclusions = replace(SCOPE, excluded_targets=[])
    assert_blocked("172.20.0.0/16", "TARGET_OUT_OF_SCOPE", scope=no_exclusions)
    assert_blocked(
        "172.20.0.128/24",
        "TARGET_OUT_OF_SCOPE",
        scope=replace(no_exclusions, ip_ranges=["172.20.0.0/25"]),
    )


def test_network_that_contains_an_excluded_ip_is_blocked() -> None:
    assert_blocked("172.20.0.0/30", "TARGET_EXCLUDED")


# --- domains ---------------------------------------------------------------


def test_exact_domain_is_allowed() -> None:
    assert_allowed("juice-shop.lab")


@pytest.mark.parametrize(
    "target",
    ["JUICE-SHOP.LAB", "juice-shop.lab.", "juice-shop.lab:3000", "juice-shop.lab:1"],
)
def test_domain_not_in_plain_form_is_blocked(target: str) -> None:
    # The tool runs the target as written, so it must be the form the check reads.
    assert_blocked(target, "TARGET_NOT_NORMALIZED")


@pytest.mark.parametrize("target", ["app.reconix.lab", "a.b.reconix.lab"])
def test_subdomain_of_wildcard_is_allowed(target: str) -> None:
    assert_allowed(target)


@pytest.mark.parametrize(
    "target",
    [
        "reconix.lab",  # "*.reconix.lab" covers subdomains only
        "evilreconix.lab",
        "reconix.lab.evil.com",
        "shop.juice-shop.lab",  # "juice-shop.lab" is exact, not a wildcard
        "example.com",
    ],
)
def test_other_domains_are_blocked(target: str) -> None:
    assert_blocked(target, "TARGET_OUT_OF_SCOPE")


def test_excluded_subdomain_is_blocked() -> None:
    assert_blocked("admin.reconix.lab", "TARGET_EXCLUDED")


def test_international_names_must_be_written_in_punycode() -> None:
    scope = replace(SCOPE, domains=["bücher.lab"])
    assert_allowed("xn--bcher-kva.lab", scope=scope)
    assert_blocked("bücher.lab", "TARGET_NOT_NORMALIZED", scope=scope)
    assert_blocked("BÜCHER.lab", "TARGET_NOT_NORMALIZED", scope=scope)


def test_look_alike_domain_is_blocked() -> None:
    # Cyrillic "а" instead of Latin "a" is a different domain.
    assert_blocked("аpp.reconix.lab.evil.com", "TARGET_NOT_NORMALIZED")
    assert_blocked("juice-shop.lаb", "TARGET_NOT_NORMALIZED")


@pytest.mark.parametrize(
    "target",
    ["app\u200b.reconix.lab", "ａｐｐ.reconix.lab", "app.reconix.lab\u202e"],
)
def test_hidden_and_full_width_characters_are_blocked(target: str) -> None:
    # IDNA would quietly turn these into "app.reconix.lab", but the tool gets the raw text.
    outcome = check_scope("NMAP", target, SCOPE, NOW)
    assert outcome.decision == Decision.BLOCKED


# --- URLs ------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "http://juice-shop.lab:3000/",
        "http://juice-shop.lab:3000/rest/products?q=1",
        "HTTP://JUICE-SHOP.LAB:3000/login",
        "https://app.reconix.lab/api",
        "https://app.reconix.lab:443/api/users",
    ],
)
def test_url_under_prefix_is_allowed(target: str) -> None:
    assert_allowed(target, tool="NUCLEI")


@pytest.mark.parametrize(
    "target",
    [
        "http://juice-shop.lab/",  # port 80, not 3000
        "https://juice-shop.lab:3000/",  # https, not http
        "https://app.reconix.lab/apiv2",  # "/api" does not cover "/apiv2"
        "https://app.reconix.lab/",
        "http://juice-shop.lab.evil.com:3000/",
    ],
)
def test_url_outside_prefix_is_blocked(target: str) -> None:
    assert_blocked(target, "TARGET_OUT_OF_SCOPE", tool="NUCLEI")


def test_excluded_url_prefix_is_blocked() -> None:
    assert_blocked("http://juice-shop.lab:3000/admin/users", "TARGET_EXCLUDED", tool="ZAP")


def test_url_on_an_excluded_host_is_blocked() -> None:
    scope = replace(SCOPE, url_prefixes=["https://admin.reconix.lab/"])
    assert_blocked("https://admin.reconix.lab/", "TARGET_EXCLUDED", tool="ZAP", scope=scope)


@pytest.mark.parametrize(
    "target",
    [
        "http://user:pass@juice-shop.lab:3000/",  # login inside the URL
        "http://juice-shop.lab:3000@evil.com/",  # host is really evil.com
        "ftp://juice-shop.lab/",
        "file:///etc/passwd",
        "http://juice-shop.lab:99999/",
        "http://",
    ],
)
def test_bad_urls_are_invalid(target: str) -> None:
    assert_blocked(target, "INVALID_TARGET", tool="NUCLEI")


# --- repo paths ------------------------------------------------------------


@pytest.mark.parametrize("target", ["/lab/vuln-repo", "/lab/vuln-repo/src", "/lab/vuln-repo/"])
def test_path_inside_repo_is_allowed(target: str) -> None:
    assert_allowed(target, tool="SEMGREP")


@pytest.mark.parametrize("target", ["/lab/vuln-repo2", "/lab", "/etc/passwd", "//lab/vuln-repo"])
def test_path_outside_repo_is_blocked(target: str) -> None:
    assert_blocked(target, "TARGET_OUT_OF_SCOPE", tool="SEMGREP")


def test_excluded_path_is_blocked() -> None:
    assert_blocked("/lab/vuln-repo/.git/config", "TARGET_EXCLUDED", tool="GITLEAKS")


@pytest.mark.parametrize(
    "target",
    [
        "/lab/vuln-repo/../../etc/passwd",
        "/lab/vuln-repo/%2e%2e/secret",
        "/lab/vuln-repo/%252e%252e/secret",
        "http://juice-shop.lab:3000/../admin",
        "..",
    ],
)
def test_path_traversal_is_blocked(target: str) -> None:
    assert_blocked(target, "PATH_TRAVERSAL", tool="SEMGREP")


# --- invalid targets -------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "juice-shop.lab; rm -rf /",
        "juice shop.lab",
        "a\\b",
        "juice-shop.lab\n",
        "-oN",
    ],
)
def test_invalid_targets_are_blocked(target: str) -> None:
    assert_blocked(target, "INVALID_TARGET")


# --- tools and time window -------------------------------------------------


def test_tool_not_in_scope_is_blocked() -> None:
    scope = replace(SCOPE, allowed_tools=["NMAP"])
    assert_blocked("http://juice-shop.lab:3000/", "TOOL_NOT_ALLOWED", tool="ZAP", scope=scope)


def test_inside_time_window_is_allowed() -> None:
    scope = replace(
        SCOPE,
        window_start=NOW - timedelta(hours=1),
        window_end=NOW + timedelta(hours=1),
    )
    assert_allowed("172.20.0.5", scope=scope)


def test_before_time_window_is_blocked() -> None:
    scope = replace(SCOPE, window_start=NOW + timedelta(minutes=1))
    assert_blocked("172.20.0.5", "OUTSIDE_TIME_WINDOW", scope=scope)


def test_after_time_window_is_blocked() -> None:
    scope = replace(SCOPE, window_end=NOW - timedelta(minutes=1))
    assert_blocked("172.20.0.5", "OUTSIDE_TIME_WINDOW", scope=scope)


def test_empty_scope_allows_nothing() -> None:
    empty = Scope(ip_ranges=[], domains=[], url_prefixes=[], repo_paths=[], excluded_targets=[])
    assert_blocked("172.20.0.5", "TARGET_OUT_OF_SCOPE", scope=empty)
    assert_blocked("juice-shop.lab", "TARGET_OUT_OF_SCOPE", scope=empty)


# --- plain form, tool kinds and wider exclusions ---------------------------


@pytest.mark.parametrize(
    "target",
    [
        "http://juice-shop.lab:3000//admin",
        "http://juice-shop.lab:3000/x//admin",
        "http://juice-shop.lab:3000/admin;x",
        "http://juice-shop.lab:3000/admin%3bx",
        "http://juice-shop.lab:3000/%2fadmin",
        "http://juice-shop.lab:3000/%252e",
        "http://juice-shop.lab:3000/./admin",
    ],
)
def test_url_path_tricks_are_blocked(target: str) -> None:
    assert_blocked(target, "TARGET_NOT_NORMALIZED", tool="ZAP")


def test_excluded_url_path_ignores_case() -> None:
    assert_blocked("http://juice-shop.lab:3000/Admin", "TARGET_EXCLUDED", tool="ZAP")
    assert_blocked("http://juice-shop.lab:3000/ADMIN/users", "TARGET_EXCLUDED", tool="ZAP")


def test_normal_url_paths_still_pass() -> None:
    assert_allowed("http://juice-shop.lab:3000/rest/products/search?q=a%20b", tool="ZAP")
    assert_allowed("http://juice-shop.lab:3000/rest/", tool="NUCLEI")


@pytest.mark.parametrize(
    ("tool", "target"),
    [
        ("NMAP", "/lab/vuln-repo"),
        ("NMAP", "http://juice-shop.lab:3000/"),
        ("NUCLEI", "172.20.0.5"),
        ("ZAP", "juice-shop.lab"),
        ("SEMGREP", "172.20.0.5"),
        ("GITLEAKS", "http://juice-shop.lab:3000/"),
    ],
)
def test_each_tool_takes_only_its_own_target_kinds(tool: str, target: str) -> None:
    assert_blocked(target, "TARGET_KIND_NOT_ALLOWED", tool=tool)


@pytest.mark.parametrize(
    ("tool", "target"),
    [
        ("NMAP", "172.20.0.5"),
        ("NMAP", "172.20.0.16/28"),
        ("NMAP", "juice-shop.lab"),
        ("NUCLEI", "juice-shop.lab"),
        ("NUCLEI", "http://juice-shop.lab:3000/"),
        ("ZAP", "http://juice-shop.lab:3000/"),
        ("SEMGREP", "/lab/vuln-repo"),
        ("GITLEAKS", "/lab/vuln-repo/src"),
    ],
)
def test_each_tool_takes_its_own_target_kinds(tool: str, target: str) -> None:
    assert_allowed(target, tool=tool)


def test_repo_path_not_in_plain_form_is_blocked() -> None:
    assert_blocked("/lab/vuln-repo//src", "TARGET_NOT_NORMALIZED", tool="SEMGREP")
    assert_blocked("/lab/vuln-repo/./src", "TARGET_NOT_NORMALIZED", tool="SEMGREP")
    assert_allowed("/lab/vuln-repo/src/", tool="SEMGREP")


def test_wildcard_exclusion_also_excludes_the_bare_domain() -> None:
    scope = replace(SCOPE, domains=["*.reconix.lab", "admin.lab"], excluded_targets=["*.admin.lab"])
    assert_blocked("admin.lab", "TARGET_EXCLUDED", scope=scope)


def test_excluded_whole_site_also_excludes_its_host() -> None:
    scope = replace(
        SCOPE,
        url_prefixes=["http://juice-shop.lab:3000/"],
        excluded_targets=["http://juice-shop.lab:3000/"],
    )
    assert_blocked("juice-shop.lab", "TARGET_EXCLUDED", scope=scope)
    assert_blocked("juice-shop.lab", "TARGET_EXCLUDED", tool="NUCLEI", scope=scope)


def test_excluded_path_does_not_exclude_the_whole_host() -> None:
    # SCOPE excludes only "http://juice-shop.lab:3000/admin".
    assert_allowed("juice-shop.lab")


def test_port_zero_is_not_the_default_port() -> None:
    assert_blocked("http://juice-shop.lab:0/", "TARGET_OUT_OF_SCOPE", tool="ZAP")
