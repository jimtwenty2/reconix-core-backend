"""The tools Core can run safely, and the exact rules for each.

The Kali catalog (`tool_specs.json`) lists every tool the container has, but the
scope check can only keep a tool inside the scope when it knows:

- which input param is the target (the one the scope check reads),
- which kinds of target the tool accepts (IP, NETWORK, DOMAIN, URL, PATH),
- which options it may take in `opts`. Any other option, or a bare word that is
  not an option's value, is blocked: a second host, a port, a proxy or a file of
  targets could otherwise slip in next to an in-scope target.

A tool without a rule here is refused (TOOL_NOT_SUPPORTED), even if the catalog has
it. Adding a tool means adding its rule and a test, reviewed by the harness owner.
Option values are still checked by the scope check: a URL, IP or host in a value
must be inside the scope too.
"""

from dataclasses import dataclass, field

from reconix_ai.harness.catalog import canonical

IP = "IP"
NETWORK = "NETWORK"
DOMAIN = "DOMAIN"
URL = "URL"
PATH = "PATH"


@dataclass(frozen=True)
class ToolRule:
    target_param: str  # the catalog input param that gets the target
    kinds: frozenset[str]  # target kinds the tool accepts
    flags: frozenset[str] = field(default_factory=frozenset)  # options without a value
    valued: frozenset[str] = field(default_factory=frozenset)  # options with one value


def rule(
    target_param: str,
    kinds: set[str],
    flags: set[str] = frozenset(),
    valued: set[str] = frozenset(),
) -> ToolRule:
    return ToolRule(target_param, frozenset(kinds), frozenset(flags), frozenset(valued))


RULES: dict[str, ToolRule] = {
    # --- network -------------------------------------------------------------
    "nmap": rule(
        "target",
        {IP, NETWORK, DOMAIN},
        flags={
            "-sV",
            "-sC",
            "-sS",
            "-sT",
            "-sU",
            "-Pn",
            "-O",
            "-A",
            "-F",
            "-p-",
            "-n",
            "-v",
            "--open",
            "--reason",
            "-T0",
            "-T1",
            "-T2",
            "-T3",
            "-T4",
            "-T5",
        },
        valued={
            "-p",
            "--top-ports",
            "--script",
            "--version-intensity",
            "--max-retries",
            "--host-timeout",
            "--max-rate",
            "--min-rate",
        },
    ),
    "masscan": rule("target", {IP, NETWORK}),  # no opts: Core sends the target only
    "rustscan": rule(
        "target",
        {IP, NETWORK, DOMAIN},
        flags={"-g", "--greppable", "--accessible", "--no-config"},
        valued={"-b", "--batch-size", "-t", "--timeout", "--ulimit", "--tries", "--scan-order"},
    ),
    # --- web -----------------------------------------------------------------
    "nuclei": rule(
        "target",
        {URL, DOMAIN},
        flags={"-silent", "-nc", "-no-color"},
        valued={
            "-severity",
            "-s",
            "-tags",
            "-etags",
            "-id",
            "-rl",
            "-rate-limit",
            "-c",
            "-timeout",
            "-retries",
        },
    ),
    "zap_scan": rule("url", {URL}),  # Core's "ZAP"; no opts
    "whatweb": rule("target", {URL}, flags={"--no-errors"}, valued={"-a", "--aggression"}),
    "nikto": rule(
        "host",
        {URL},  # a full URL, so the port is the one the scope check read
        flags={"-ssl", "-nossl", "-no404"},
        valued={"-Tuning", "-maxtime", "-Display", "-timeout"},
    ),
    "sqlmap": rule(
        "url",
        {URL},
        flags={
            "--dbs",
            "--tables",
            "--banner",
            "--current-user",
            "--current-db",
            "--forms",
            "--random-agent",
            "--smart",
            "--batch",
        },
        valued={"--level", "--risk", "--technique", "-p", "--threads", "--crawl"},
    ),
    "wpscan": rule(
        "url",
        {URL},
        flags={"--random-user-agent", "--disable-tls-checks", "--no-banner"},
        valued={"--enumerate", "-e", "--plugins-detection"},
    ),
    "httpx_probe": rule(
        "target",
        {URL},
        flags={
            "-title",
            "-tech-detect",
            "-td",
            "-status-code",
            "-sc",
            "-server",
            "-web-server",
            "-content-length",
            "-cl",
            "-silent",
        },
    ),
    "testssl": rule(
        "target",
        {URL},
        flags={"-U", "-p", "-S", "-P", "-E", "-s", "-f", "-e", "--fast", "--quiet", "--sneaky"},
    ),
    # --- DNS -----------------------------------------------------------------
    "dnsrecon": rule("domain", {DOMAIN}, valued={"-t"}),
    # --- code (a folder of sent code; these reach no target over the network) -
    "semgrep": rule(
        "path",
        {PATH},
        flags={"--no-git-ignore"},
        valued={"--exclude", "--include", "--severity", "--max-target-bytes", "--jobs", "-j"},
    ),
    "gitleaks": rule("path", {PATH}, flags={"--no-git", "--redact"}, valued={"--log-level"}),
    "trivy": rule(
        "path",
        {PATH},
        flags={"--offline-scan", "--skip-db-update"},
        valued={"--scanners", "--severity", "--skip-dirs"},
    ),
    "osv_scanner": rule("path", {PATH}, flags={"-r", "--recursive", "--no-ignore"}),
    "grype": rule("target", {PATH}, flags={"--only-fixed"}, valued={"--fail-on", "--scope"}),
    "syft": rule("target", {PATH}, valued={"--scope"}),
}


def rule_for(tool: str) -> ToolRule | None:
    return RULES.get(canonical(tool))


def is_supported(tool: str) -> bool:
    return rule_for(tool) is not None


def supported_tools() -> list[str]:
    """Every tool Core can run, UPPERCASE ("ZAP_SCAN" is Core's "ZAP")."""
    return sorted(name.upper() for name in RULES)


def option_values(tool: str, arguments: list[str] | tuple[str, ...]) -> list[str] | None:
    """The values in the arguments, if every argument is an allowed option or the value of
    one; None if any is not. "--opt=value" counts as the option and its value."""
    found = rule_for(tool)
    if found is None:
        return None
    values: list[str] = []
    expects_value = False
    for argument in arguments:
        if expects_value:
            values.append(argument)
            expects_value = False
            continue
        option, equals, value = argument.partition("=")
        if equals and option in found.valued:
            values.append(value)
        elif not equals and argument in found.valued:
            expects_value = True
        elif not equals and argument in found.flags:
            continue
        else:
            return None
    return None if expects_value else values
