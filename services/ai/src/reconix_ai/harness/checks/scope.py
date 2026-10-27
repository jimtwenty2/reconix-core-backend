"""Scope check: the second of the 5 checks.

A target is allowed only if it is inside the approved scope:
- an IP in an allowed range (or, for nmap, a whole network inside one),
- an exact domain or a subdomain of an allowed "*.domain",
- a URL that starts with an allowed URL prefix,
- a path inside an allowed repo folder.

Excluded targets are always blocked, any ".." is blocked, and the tool and the
time window must be allowed too. The check never reads the database or the
network; it only looks at the strings it is given.
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
    if any(matches_entry(parsed, entry) for entry in scope.excluded_targets):
        return blocked("TARGET_EXCLUDED")
    if not is_in_scope(parsed, scope):
        return blocked("TARGET_OUT_OF_SCOPE")
    return ALLOWED


def has_path_traversal(target: str) -> bool:
    # Decode twice so "%2e%2e" and "%252e%252e" are caught too.
    return ".." in unquote(unquote(target))


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
        port=port or URL_SCHEMES[scheme],
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
