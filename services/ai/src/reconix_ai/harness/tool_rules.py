"""The tools Core can run safely, and the exact rules for each.

The Kali catalog (`tool_specs.json`) lists every tool the container has, but the
scope check can only keep a tool inside the scope when it knows:

- which input param is the target (the one the scope check reads),
- which kinds of target the tool accepts (IP, NETWORK, DOMAIN, URL, PATH),
- which options it may take in `opts`, and what each option's value may look like.
  Any other option, a bare word that is not an option's value, or a value that does
  not match its pattern is blocked: a second host, a port, a proxy, a script file or
  a file of targets could otherwise slip in next to an in-scope target.

A value never starts with "-": some tools (wpscan) treat the next word as a new
option when it does, so "-e --url=x" would smuggle in a second target.

`forced` arguments are always sent after the approved ones; they turn off behaviour
that would leave the scope without any target being written (following redirects).

A tool without a rule here is refused (TOOL_NOT_SUPPORTED), even if the catalog has
it. Adding a tool means adding its rule and a test, reviewed by the harness owner.
Option values are still checked by the scope check: a URL, IP or host in a value
must be inside the scope too.
"""

import re
from dataclasses import dataclass, field

from reconix_ai.harness.catalog import canonical

IP = "IP"
NETWORK = "NETWORK"
DOMAIN = "DOMAIN"
URL = "URL"
PATH = "PATH"

NUMBER = re.compile(r"^[0-9]{1,6}$")
PORTS = re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$")
DURATION = re.compile(r"^[0-9]{1,6}(ms|s|m|h)?$")
WORDS = re.compile(r"^[a-z0-9_]+(-[a-z0-9_]+)*(,[a-z0-9_]+(-[a-z0-9_]+)*)*$")  # "cve,xss"
# Relative glob of files inside the scanned folder: no "..", no leading "/" or "-".
GLOB = re.compile(r"^(?!.*\.\.)[A-Za-z0-9_*][A-Za-z0-9_.*/-]*$")

# nmap script names (never a path) and the categories that leave the target or harm it.
NMAP_SCRIPTS = WORDS
BLOCKED_NMAP_SCRIPTS = {
    "all", "broadcast", "external", "dos", "exploit", "brute", "intrusive", "malware",
    "fuzzer",
}  # fmt: skip


def one_of(*choices: str) -> re.Pattern[str]:
    """A comma list of these words, e.g. one_of("std", "srv") matches "std,srv"."""
    word = "|".join(re.escape(choice) for choice in choices)
    return re.compile(rf"^({word})(,({word}))*$")


@dataclass(frozen=True)
class ToolRule:
    target_param: str  # the catalog input param that gets the target
    kinds: frozenset[str]  # target kinds the tool accepts
    flags: frozenset[str] = field(default_factory=frozenset)  # options without a value
    valued: dict[str, re.Pattern[str]] = field(default_factory=dict)  # option -> its value
    forced: tuple[str, ...] = ()  # always sent after the approved arguments


def rule(
    target_param: str,
    kinds: set[str],
    flags: set[str] = frozenset(),
    valued: dict[str, re.Pattern[str]] | None = None,
    forced: tuple[str, ...] = (),
) -> ToolRule:
    return ToolRule(target_param, frozenset(kinds), frozenset(flags), dict(valued or {}), forced)


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
            "-p": PORTS,
            "--top-ports": NUMBER,
            "--script": NMAP_SCRIPTS,
            "--version-intensity": re.compile(r"^[0-9]$"),
            "--max-retries": NUMBER,
            "--host-timeout": DURATION,
            "--max-rate": NUMBER,
            "--min-rate": NUMBER,
        },
    ),  # fmt: skip
    "masscan": rule("target", {IP, NETWORK}),  # no opts: Core sends the target only
    "rustscan": rule(
        "target",
        {IP, NETWORK, DOMAIN},
        flags={"-g", "--greppable", "--accessible", "--no-config"},
        valued={
            "-b": NUMBER,
            "--batch-size": NUMBER,
            "-t": NUMBER,
            "--timeout": NUMBER,
            "--ulimit": NUMBER,
            "--tries": NUMBER,
            "--scan-order": one_of("serial", "random"),
        },
    ),
    # --- web -----------------------------------------------------------------
    "nuclei": rule(
        "target",
        {URL, DOMAIN},
        flags={"-silent", "-nc", "-no-color"},
        valued={
            "-severity": one_of("info", "low", "medium", "high", "critical", "unknown"),
            "-s": one_of("info", "low", "medium", "high", "critical", "unknown"),
            "-tags": WORDS,
            "-etags": WORDS,
            "-id": re.compile(
                r"^[A-Za-z0-9_]+(-[A-Za-z0-9_]+)*(,[A-Za-z0-9_]+(-[A-Za-z0-9_]+)*)*$"
            ),
            "-rl": NUMBER,
            "-rate-limit": NUMBER,
            "-c": NUMBER,
            "-timeout": NUMBER,
            "-retries": NUMBER,
        },
    ),
    "zap_scan": rule("url", {URL}),  # Core's "ZAP"; no opts
    "whatweb": rule(
        "target",
        {URL},
        flags={"--no-errors"},
        valued={"-a": re.compile(r"^[1-4]$"), "--aggression": re.compile(r"^[1-4]$")},
        forced=("--follow-redirect=never",),  # its default follows any redirect
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
        valued={
            "--level": re.compile(r"^[1-5]$"),
            "--risk": re.compile(r"^[1-3]$"),
            "--technique": re.compile(r"^[BEUSTQ]{1,6}$"),
            "-p": re.compile(r"^[A-Za-z0-9_\[\]]+(,[A-Za-z0-9_\[\]]+)*$"),  # parameter names
            "--threads": re.compile(r"^([1-9]|10)$"),
            "--crawl": re.compile(r"^[0-3]$"),
        },
        forced=("--ignore-redirects",),
    ),  # fmt: skip
    "wpscan": rule(
        "url",
        {URL},
        flags={"--random-user-agent", "--disable-tls-checks", "--no-banner"},
        valued={
            "--enumerate": re.compile(r"^[a-z0-9]+(-[0-9]+)?(,[a-z0-9]+(-[0-9]+)?)*$"),
            "-e": re.compile(r"^[a-z0-9]+(-[0-9]+)?(,[a-z0-9]+(-[0-9]+)?)*$"),
            "--plugins-detection": one_of("mixed", "passive", "aggressive"),
        },
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
    ),  # fmt: skip
    "testssl": rule(
        "target",
        {URL},
        flags={"-U", "-p", "-S", "-P", "-E", "-s", "-f", "-e", "--fast", "--quiet", "--sneaky"},
    ),
    # --- DNS -----------------------------------------------------------------
    # Only record lookups on the domain itself: no zone transfer, brute force, TLD
    # sweep or third-party search (axfr, brt, tld, crt, bing, ...).
    "dnsrecon": rule("domain", {DOMAIN}, valued={"-t": one_of("std", "srv", "caa")}),
    # --- code (a folder of sent code; these reach no target over the network) -
    "semgrep": rule(
        "path",
        {PATH},
        flags={"--no-git-ignore"},
        valued={
            "--exclude": GLOB,
            "--include": GLOB,
            "--severity": one_of("INFO", "WARNING", "ERROR"),
            "--max-target-bytes": NUMBER,
            "--jobs": NUMBER,
            "-j": NUMBER,
        },
    ),
    "gitleaks": rule(
        "path",
        {PATH},
        flags={"--no-git", "--redact"},
        valued={"--log-level": one_of("trace", "debug", "info", "warn", "error", "fatal")},
    ),
    "trivy": rule(
        "path",
        {PATH},
        flags={"--offline-scan", "--skip-db-update"},
        valued={
            "--scanners": one_of("vuln", "misconfig", "secret", "license"),
            "--severity": one_of("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
            "--skip-dirs": GLOB,
        },
    ),
    "osv_scanner": rule("path", {PATH}, flags={"-r", "--recursive", "--no-ignore"}),
    "grype": rule(
        "target",
        {PATH},
        flags={"--only-fixed"},
        valued={
            "--fail-on": one_of("negligible", "low", "medium", "high", "critical"),
            "--scope": one_of("squashed", "all-layers"),
        },
    ),
    "syft": rule("target", {PATH}, valued={"--scope": one_of("squashed", "all-layers")}),
}


def rule_for(tool: str) -> ToolRule | None:
    return RULES.get(canonical(tool))


def is_supported(tool: str) -> bool:
    return rule_for(tool) is not None


def supported_tools() -> list[str]:
    """Every tool Core can run, UPPERCASE ("ZAP_SCAN" is Core's "ZAP")."""
    return sorted(name.upper() for name in RULES)


def option_values(tool: str, arguments: list[str] | tuple[str, ...]) -> list[str] | None:
    """The values in the arguments, if every argument is an allowed option or a valid value
    of one; None if any is not. "--opt=value" counts as the option and its value."""
    found = rule_for(tool)
    if found is None:
        return None
    values: list[str] = []
    pending: str | None = None  # the option waiting for its value
    for argument in arguments:
        if pending is not None:
            if not value_ok(found, pending, argument):
                return None
            values.append(argument)
            pending = None
            continue
        option, equals, value = argument.partition("=")
        if equals and option in found.valued:
            if not value_ok(found, option, value):
                return None
            values.append(value)
        elif not equals and argument in found.valued:
            pending = argument
        elif not equals and argument in found.flags:
            continue
        else:
            return None
    return None if pending is not None else values


def value_ok(found: ToolRule, option: str, value: str) -> bool:
    if value.startswith("-") or not found.valued[option].match(value):
        return False
    if found is RULES["nmap"] and option == "--script":
        return BLOCKED_NMAP_SCRIPTS.isdisjoint(value.split(","))
    return True
