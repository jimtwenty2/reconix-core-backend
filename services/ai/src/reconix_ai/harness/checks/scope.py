"""Scope check: the second of the 5 checks.

A target is allowed only if it is inside the approved scope:
- an IP in an allowed range (or, for nmap, a whole network inside one),
- an exact domain or a subdomain of an allowed "*.domain",
- a URL that starts with an allowed URL prefix,
- a path inside an allowed repo folder.

Excluded targets are always blocked, any ".." is blocked, and the tool and the
time window must be allowed too. Each tool only takes its own kinds of target
(nmap never gets a repo path). When the scope lists allowed ports, nmap must
name its ports with -p and every one must be allowed (check_ports).

The tool runs the target string exactly as given, so a target must already be
in its plain form: ASCII only (punycode for international names), lower case,
no trailing dot, no port on a domain, and no URL path tricks like "//",
"%2f" or ";". Anything else is blocked instead of being cleaned up, so what was
checked is always what runs.

The check never reads the database or the network; it only looks at the
strings it is given. So an excluded IP does not exclude a domain that resolves
to it: the API must resolve domains first if that matters.
"""

import ipaddress
import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Protocol
from urllib.parse import unquote, urlsplit

from reconix_ai.harness.checks.result import ALLOWED, CheckOutcome, blocked

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

URL_SCHEMES = {"http": 80, "https": 443}
HOST_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
BAD_TARGET_CHARACTERS = re.compile(r"[\s\\\x00-\x1f\x7f]")
# Path parts some web servers read differently from this check.
TRICKY_URL_PATH = re.compile(r"//|;|%(2f|5c|2e|3b|25|00)|(^|/)\.(/|$)", re.IGNORECASE)
PORT_LIST = re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$")
MAX_PORT = 65535
# nmap options that pick their own ports, so they can reach ports outside the list.
OWN_PORT_OPTIONS = {"--top-ports", "-F", "-p-"}


class ScopeRules(Protocol):
    """The fields of the approved scope this check needs.

    The shared ApprovedScope in core/interfaces.py has all of them, so the API
    can pass it in as it is.
    """

    @property
    def ip_ranges(self) -> Sequence[str]: ...
    @property
    def domains(self) -> Sequence[str]: ...
    @property
    def url_prefixes(self) -> Sequence[str]: ...
    @property
    def repo_paths(self) -> Sequence[str]: ...
    @property
    def excluded_targets(self) -> Sequence[str]: ...
    @property
    def allowed_tools(self) -> Sequence[str]: ...
    @property
    def window_start(self) -> datetime | None: ...
    @property
    def window_end(self) -> datetime | None: ...


class TargetKind(StrEnum):
    IP = "IP"
    NETWORK = "NETWORK"
    DOMAIN = "DOMAIN"
    URL = "URL"
    PATH = "PATH"


TOOL_TARGET_KINDS = {
    "NMAP": {TargetKind.IP, TargetKind.NETWORK, TargetKind.DOMAIN},
    "NUCLEI": {TargetKind.URL, TargetKind.DOMAIN},
    "ZAP": {TargetKind.URL},
    "SEMGREP": {TargetKind.PATH},
    "GITLEAKS": {TargetKind.PATH},
}


@dataclass(frozen=True)
class Url:
    scheme: str
    host: str  # a normalized domain, or an IP written as text
    port: int
    path: str


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    ip: IpAddress | None = None
    network: IpNetwork | None = None
    host: str | None = None
    url: Url | None = None
    path: PurePosixPath | None = None


def check_scope(tool: str, target: str, scope: ScopeRules, now: datetime) -> CheckOutcome:
    if scope.window_start is not None and now < scope.window_start:
        return blocked("OUTSIDE_TIME_WINDOW")
    if scope.window_end is not None and now > scope.window_end:
        return blocked("OUTSIDE_TIME_WINDOW")
    if tool not in scope.allowed_tools:
        return blocked("TOOL_NOT_ALLOWED")
    if has_path_traversal(target):
        return blocked("PATH_TRAVERSAL")

    parsed = parse_target(target)
    if parsed is None:
        return blocked("INVALID_TARGET")
    if not is_plain_form(target, parsed):
        return blocked("TARGET_NOT_NORMALIZED")
    if parsed.kind not in TOOL_TARGET_KINDS.get(tool.upper(), set()):
        return blocked("TARGET_KIND_NOT_ALLOWED")
    if any(is_excluded(parsed, entry) for entry in scope.excluded_targets):
        return blocked("TARGET_EXCLUDED")
    if not is_in_scope(parsed, scope):
        return blocked("TARGET_OUT_OF_SCOPE")
    return ALLOWED


def check_ports(tool: str, arguments: Sequence[str], scope: ScopeRules) -> CheckOutcome:
    """With allowed ports in the scope, nmap scans only those: every -p value must be
    inside them, and options that pick their own ports are blocked. A scope with no
    allowed ports (an older scope, or a web or source scope) puts no limit on ports.
    The other tools take their port from the target, which the scope check covers."""
    allowed = set(getattr(scope, "allowed_ports", None) or ())
    if not allowed or tool.upper() != "NMAP":
        return ALLOWED
    named = False
    for index, argument in enumerate(arguments):
        if argument in OWN_PORT_OPTIONS:
            return blocked("PORTS_OUT_OF_SCOPE")
        if argument.startswith("-p") and argument != "-p":
            return blocked("BAD_PORTS")  # "-p22" or "-p-": only "-p", then its value
        if argument != "-p":
            continue
        value = arguments[index + 1] if index + 1 < len(arguments) else ""
        ports = port_set(value)
        if ports is None:
            return blocked("BAD_PORTS")
        if not ports <= allowed:
            return blocked("PORTS_OUT_OF_SCOPE")
        named = True
    return ALLOWED if named else blocked("PORTS_NOT_GIVEN")


def port_set(value: str) -> set[int] | None:
    """ "22,80,8000-8010" as a set of ports, or None if it is not written that way."""
    if not PORT_LIST.match(value):
        return None
    ports: set[int] = set()
    for part in value.split(","):
        first, _, last = part.partition("-")
        low, high = int(first), int(last or first)
        if not 1 <= low <= high <= MAX_PORT:
            return None
        ports.update(range(low, high + 1))
    return ports


def has_path_traversal(target: str) -> bool:
    # Decode twice so "%2e%2e" and "%252e%252e" are caught too.
    return ".." in unquote(unquote(target))


def is_plain_form(text: str, target: Target) -> bool:
    """True if the target is written exactly as the check reads it."""
    if not text.isascii():
        return False
    match target.kind:
        case TargetKind.DOMAIN:
            return text == target.host
        case TargetKind.PATH:
            return text.rstrip("/") == str(target.path).rstrip("/")
        case TargetKind.URL:
            return TRICKY_URL_PATH.search(urlsplit(text).path) is None
    return True


# --- reading a target ------------------------------------------------------


def parse_target(text: str) -> Target | None:
    """Turn a target string into a Target, or None if it is not a valid target."""
    if not text or BAD_TARGET_CHARACTERS.search(text):
        return None
    if "://" in text:
        url = parse_url(text)
        return Target(kind=TargetKind.URL, url=url) if url else None
    if text.startswith("/"):
        return Target(kind=TargetKind.PATH, path=PurePosixPath(posixpath.normpath(text)))

    ip = parse_ip(text)
    if ip is not None:
        return Target(kind=TargetKind.IP, ip=ip)
    if "/" in text:
        network = parse_network(text)
        return Target(kind=TargetKind.NETWORK, network=network) if network else None

    host = normalize_host(strip_port(text))
    return Target(kind=TargetKind.DOMAIN, host=host) if host else None


def parse_ip(text: str) -> IpAddress | None:
    try:
        ip = ipaddress.ip_address(text.removeprefix("[").removesuffix("]"))
    except ValueError:
        return None
    # "::ffff:10.0.0.1" is the same machine as "10.0.0.1".
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def parse_network(text: str) -> IpNetwork | None:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def strip_port(text: str) -> str:
    host, colon, port = text.rpartition(":")
    return host if colon and port.isdigit() else text


def normalize_host(text: str) -> str | None:
    """Lower case, no trailing dot, international names in punycode ("xn--...")."""
    text = text.rstrip(".").lower()
    try:
        host = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return host if HOST_PATTERN.match(host) else None


def parse_url(text: str) -> Url | None:
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in URL_SCHEMES or "@" in parts.netloc or not parts.hostname:
        return None

    ip = parse_ip(parts.hostname)
    host = str(ip) if ip is not None else normalize_host(parts.hostname)
    if host is None:
        return None
    return Url(
        scheme=scheme,
        host=host,
        port=port if port is not None else URL_SCHEMES[scheme],
        path=posixpath.normpath(unquote(parts.path) or "/"),
    )


# --- matching a target against scope entries -------------------------------


def is_in_scope(target: Target, scope: ScopeRules) -> bool:
    match target.kind:
        case TargetKind.NETWORK:
            # The whole network must fit inside one allowed range, not just touch it.
            return any(network_inside(target.network, entry) for entry in scope.ip_ranges)
        case TargetKind.IP:
            entries = scope.ip_ranges
        case TargetKind.DOMAIN:
            entries = scope.domains
        case TargetKind.URL:
            entries = scope.url_prefixes
        case TargetKind.PATH:
            entries = scope.repo_paths
    return any(matches_entry(target, entry) for entry in entries)


def matches_entry(target: Target, entry: str) -> bool:
    """True if the target is covered by one scope entry (an IP, range, domain, URL or path)."""
    rule = parse_target(entry.removeprefix("*."))
    if rule is None:
        return False
    wildcard = entry.startswith("*.")

    match target.kind:
        case TargetKind.IP:
            return ip_matches(target.ip, rule)
        case TargetKind.NETWORK:
            return network_overlaps(target.network, rule)
        case TargetKind.DOMAIN:
            return rule.kind == TargetKind.DOMAIN and host_matches(target.host, rule.host, wildcard)
        case TargetKind.URL:
            return url_matches(target.url, rule, wildcard)
        case TargetKind.PATH:
            return rule.kind == TargetKind.PATH and target.path.is_relative_to(rule.path)
    return False


def is_excluded(target: Target, entry: str) -> bool:
    """Like matches_entry, but wider: an exclusion should rather block too much."""
    if matches_entry(target, entry):
        return True
    # "*.admin.lab" also excludes "admin.lab" itself.
    if entry.startswith("*.") and matches_entry(target, entry.removeprefix("*.")):
        return True
    rule = parse_target(entry)
    if rule is None or rule.kind != TargetKind.URL:
        return False
    # An excluded whole site ("http://admin.lab/") also excludes its host as a
    # plain domain or IP. An excluded path only excludes URLs under it.
    if target.kind == TargetKind.DOMAIN and rule.url.path == "/":
        return target.host == rule.url.host
    if target.kind == TargetKind.IP and rule.url.path == "/":
        return str(target.ip) == rule.url.host
    # Some servers ignore case in paths, so "/Admin" is excluded like "/admin".
    if target.kind == TargetKind.URL:
        return (
            target.url.host == rule.url.host
            and target.url.port == rule.url.port
            and path_starts_with(target.url.path.lower(), rule.url.path.lower())
        )
    return False


def ip_matches(ip: IpAddress, rule: Target) -> bool:
    if rule.kind == TargetKind.IP:
        return ip == rule.ip
    if rule.kind == TargetKind.NETWORK:
        return ip.version == rule.network.version and ip in rule.network
    return False


def network_inside(network: IpNetwork, entry: str) -> bool:
    rule = parse_target(entry)
    if rule is None:
        return False
    if rule.kind == TargetKind.IP:
        return network.num_addresses == 1 and network.network_address == rule.ip
    if rule.kind == TargetKind.NETWORK:
        return network.version == rule.network.version and network.subnet_of(rule.network)
    return False


def network_overlaps(network: IpNetwork, rule: Target) -> bool:
    """Used for excluded targets: touching any excluded address is enough to block."""
    if rule.kind == TargetKind.IP:
        return rule.ip.version == network.version and rule.ip in network
    if rule.kind == TargetKind.NETWORK:
        return network.version == rule.network.version and network.overlaps(rule.network)
    return False


def host_matches(host: str, rule_host: str, wildcard: bool) -> bool:
    if wildcard:
        return host.endswith("." + rule_host)
    return host == rule_host


def url_matches(url: Url, rule: Target, wildcard: bool) -> bool:
    if rule.kind == TargetKind.URL:
        return (
            url.scheme == rule.url.scheme
            and url.host == rule.url.host
            and url.port == rule.url.port
            and path_starts_with(url.path, rule.url.path)
        )
    # An excluded IP or domain also excludes every URL on that host.
    host_ip = parse_ip(url.host)
    if host_ip is not None:
        return ip_matches(host_ip, rule)
    return rule.kind == TargetKind.DOMAIN and host_matches(url.host, rule.host, wildcard)


def path_starts_with(path: str, prefix: str) -> bool:
    """ "/app" covers "/app" and "/app/x", but not "/application"."""
    if prefix == "/" or path == prefix:
        return True
    return path.startswith(prefix.rstrip("/") + "/")
