"""Is this a valid target for that template? Strict, per-template checks of typed input.

Two callers: `/template` (the operator chose the template, so the target must fit it) and
the free-text parser (it picks the template from the target's shape, then reads the value
here). Rule-based and offline: nothing here touches the network. A malformed value (an
IPv4 octet over 255, a range wider than /16, a URL without a host) raises
`StoreValidationError`; a text that holds no target of the kind returns None.

`validate_target()` checks one typed value for the Start prompt's feedback and never
raises; it is the only function here that reads the disk (does a local folder exist).
The backend's scope check stays the authority.
"""

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Union
from urllib.parse import SplitResult, urlsplit

from ..models.parser import ParsedTarget
from .assessment import clean_request
from .errors import StoreValidationError
from .redact import redact

# --- what a target looks like inside a sentence -------------------------------------------
URL = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
GIT_URL = re.compile(r"\b(?:ssh|git)://[^\s'\"<>]+", re.IGNORECASE)
GIT_REF = re.compile(
    r"\b(?:git@[^\s'\"<>]+|(?:github\.com|gitlab\.com|bitbucket\.org)/"
    r"[^\s'\"<>]+)",
    re.IGNORECASE,
)
HOST = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
# Loose on purpose: 10.0.0.300 is found here and then refused by ipv4(), not ignored.
IPV4_LIKE = re.compile(r"(?<![\w.])\d+(?:\.\d+){3}(?:/\d+)?(?!\w|\.\d)")
LOCAL_PATH = re.compile(r"(?:^|\s)((?:~|\.{1,2})?/[^\s'\"<>]+|[A-Za-z]:\\[^\s'\"<>]+)")
API_PATH = re.compile(r"/(?:api|v\d+|graphql|rest)\b", re.IGNORECASE)

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)
_TRAILING = ".,;:!?)]}'\""

WIDEST_RANGE = 16  # /16 = 65,536 addresses; anything wider is refused


def _clean(token: str) -> str:
    return token.rstrip(_TRAILING)


def _split(url: str) -> Optional[SplitResult]:
    """`url` split into its parts, or None when it can't be read as a URL.

    `urlsplit()` raises ValueError on a stray bracket ("http://x]x[" reads as a broken IPv6
    literal); typed text must never crash the app, so such a value is simply not a URL.
    """
    try:
        return urlsplit(url)
    except ValueError:
        return None


# --- single values -------------------------------------------------------------------------
def as_network(text: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """`text` as an address range (a single address is a /32), or None for anything else."""
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None


def ipv4(token: str) -> str:
    """A normalized IPv4 address or range ("10.0.0.5/24" -> "10.0.0.0/24"); raises if invalid."""
    if "/" in token:
        try:
            network = ipaddress.IPv4Network(token, strict=False)
        except ValueError:
            raise StoreValidationError(
                f"{token} isn't a valid IPv4 range — e.g. 10.0.0.0/24"
            ) from None
        if network.prefixlen < WIDEST_RANGE:
            raise StoreValidationError(
                f"{token} is too wide to test — use a /{WIDEST_RANGE} or smaller range."
            )
        _usable(network.network_address, token)
        return str(network) if network.prefixlen < 32 else str(network.network_address)
    try:
        address = ipaddress.IPv4Address(token)
    except ValueError:
        raise StoreValidationError(
            f"{token} isn't a valid IPv4 address — four numbers from 0 to 255."
        ) from None
    _usable(address, token)
    return str(address)


def _usable(address: ipaddress.IPv4Address, token: str) -> None:
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        raise StoreValidationError(f"{token} isn't an address that can be tested.")


def host_value(host: str) -> str:
    """A lower-case hostname or a normalized IPv4 address; raises if it is neither."""
    host = host.strip().rstrip(".").lower()
    if IPV4_LIKE.fullmatch(host):
        return ipv4(host)
    if _HOSTNAME.match(host):
        return host
    raise StoreValidationError(f"{host or 'That'} isn't a valid host name.")


def looks_api(url: str) -> bool:
    parts = _split(url)
    return bool(parts and API_PATH.search(parts.path or ""))


def url_target(url: str, kind: str) -> ParsedTarget:
    """A web or API target from an http(s) URL. Credentials in the URL are dropped."""
    url = _clean(url)
    parts = _split(url)
    if parts is None:
        raise StoreValidationError(f"{redact(url)} isn't a valid URL.")
    if not parts.hostname:
        raise StoreValidationError(f"{redact(url)} has no host name.")
    try:
        port = parts.port
    except ValueError:
        raise StoreValidationError(f"{redact(url)} has an invalid port.") from None
    host = parts.hostname if ":" in parts.hostname else host_value(parts.hostname)
    shown = f"[{host}]" if ":" in host else host  # IPv6 literals keep their brackets
    base = f"{parts.scheme.lower()}://{shown}" + (f":{port}" if port else "")  # never user:pass@
    label = "API service" if kind == "api" else "web application"
    return ParsedTarget(kind, host, base, label, kind, confident=True)


GITHUB_ONLY = "Only GitHub repos are supported (https://github.com/<owner>/<repo>)."
_REPO_PART = re.compile(r"[\w.-]+")  # the backend's GITHUB_URL takes only these characters


def _is_repo_ref(ref: str) -> bool:
    """True when `ref` names a git repository (any host), so a non-GitHub one is refused
    clearly instead of being read as a web site. An ordinary https site is not a repo."""
    lower = ref.lower()
    if lower.startswith(("git@", "ssh://", "git://")):
        return True
    if lower.startswith(("http://", "https://")):
        parts = _split(_clean(ref))
        if parts is None:
            return False
        host = (parts.hostname or "").removeprefix("www.")
        return host in _GIT_HOSTS or parts.path.rstrip("/").endswith(".git")
    return lower.removeprefix("www.").startswith(_GIT_HOSTS)


def github_repo(ref: str) -> str:
    """`ref` as the one form the backend clones: https://github.com/<owner>/<repo>.

    Takes http(s)://, www., no scheme, git@github.com:o/r(.git), ssh:// and git:// forms;
    drops credentials, a port, /tree/… or any path past owner/repo, ?query, #fragment, a
    trailing / and .git. Any other host raises GITHUB_ONLY (GitHub-only is the backend's
    rule); a GitHub ref without owner/repo raises "isn't a repository".
    """
    ref = _clean(ref.strip())
    if ref.lower().startswith("git@"):
        host, _, path = ref[4:].partition(":")
    else:
        parts = _split(ref if "://" in ref else f"https://{ref}")
        if parts is None or parts.scheme.lower() not in ("http", "https", "ssh", "git"):
            raise StoreValidationError(GITHUB_ONLY)
        host, path = parts.hostname or "", parts.path
    if host.lower().removeprefix("www.") != "github.com":
        raise StoreValidationError(GITHUB_ONLY)
    owner, repo = ([s for s in path.split("/") if s] + ["", ""])[:2]
    repo = repo.removesuffix(".git")
    if not all(_REPO_PART.fullmatch(p) and p.strip(".") for p in (owner, repo)):
        raise StoreValidationError(
            f"{redact(ref)} isn't a repository — e.g. https://github.com/acme/app"
        )
    return f"https://github.com/{owner}/{repo}"


# --- one finder per template ----------------------------------------------------------------
DASH_RANGE_UNSUPPORTED = (
    "Dash ranges aren't supported by the scope yet — use CIDR, e.g. 10.0.0.0/27."
)


# A range written with a dash (also spaced, en/em dash), "..", or "to" between two addresses.
_ANY_RANGE = re.compile(
    r"(\d+(?:\.\d+){3})\s*(?:-|\u2013|\u2014|\.\.|\bto\b)\s*"
    r"(\d+(?:\.\d+){3}|\d+)\b",
    re.IGNORECASE,
)


def _refuse_dash_range(text: str) -> None:
    """A dash range (10.0.0.1-10.0.0.20, or spaced, with an en dash, "..", "to") anywhere in
    `text` raises: the scope takes one address or a CIDR range, and reading only the first
    address would test less than was typed."""
    dash = _ANY_RANGE.search(text)
    if dash:
        check = _dash_range(dash.group(1), dash.group(2))
        raise StoreValidationError(check.error or DASH_RANGE_UNSUPPORTED)


def network_target(text: str) -> Optional[ParsedTarget]:
    _refuse_dash_range(text)
    found = IPV4_LIKE.search(text)
    if found:
        value = ipv4(_clean(found.group(0)))
        label = "network range" if "/" in value else "network host"
        return ParsedTarget("network", value, value, label, "network", True)
    url = URL.search(text)
    host = None
    if url:
        parts = _split(_clean(url.group(0)))
        if parts is None:
            raise StoreValidationError(
                f"{redact(_clean(url.group(0)))} isn't a valid URL."
            )
        host = parts.hostname
    if not host:
        bare = HOST.search(text)
        host = bare.group(0) if bare else None
    if host:
        value = host_value(host)
        return ParsedTarget("network", value, value, "network host", "network", True)
    return None


def web_target(text: str, kind: str = "web_url") -> Optional[ParsedTarget]:
    url = URL.search(text)
    if url:
        return url_target(url.group(0), kind)
    _refuse_dash_range(text)
    found = IPV4_LIKE.search(text)
    if found and "/" not in found.group(0):  # a range is not a site
        return url_target(f"https://{ipv4(_clean(found.group(0)))}", kind)
    bare = HOST.search(text)
    if bare:
        return url_target(f"https://{host_value(bare.group(0))}", kind)
    return None


def api_target(text: str) -> Optional[ParsedTarget]:
    return web_target(text, "api")


def source_target(text: str) -> Optional[ParsedTarget]:
    # URL first: GIT_REF also matches inside https://github.com/…, without its scheme.
    for pattern in (URL, GIT_URL, GIT_REF):
        found = pattern.search(text)
        if found and _is_repo_ref(found.group(0)):
            return _source(github_repo(found.group(0)))
    path = LOCAL_PATH.search(text)
    if path:
        return _source(_clean(path.group(1)).rstrip("/") or "/")
    return None


def _source(ref: str) -> ParsedTarget:
    return ParsedTarget("source", ref, ref, "source repository", "source", True)


FINDERS: Dict[str, Callable[[str], Optional[ParsedTarget]]] = {
    "network": network_target,
    "web_url": web_target,
    "api": api_target,
    "source": source_target,
}


# --- the store function -----------------------------------------------------------------------
def needs(template_id: str) -> str:
    """What a template's target must be, as one sentence with an example."""
    from .templates import MODULES  # (imported here: this module stays a leaf)

    spec = MODULES[template_id].SPEC
    return f"{spec.name} needs {spec.target_hint} — e.g. {spec.example}"


def check_target(template_id: str, text: str) -> ParsedTarget:
    """The target in `text`, validated for `template_id`; raises with what to type instead."""
    from .templates import get_template  # (imported here: this module stays a leaf)

    get_template(template_id)  # unknown or not in the demo: refused
    finder = FINDERS[template_id]
    if not text.strip():
        raise StoreValidationError(needs(template_id))
    found = finder(clean_request(text))
    if found is None:
        found = _single_label(template_id, clean_request(text))
    if found is None:
        raise StoreValidationError(needs(template_id))
    return found


def _single_label(template_id: str, text: str) -> Optional[ParsedTarget]:
    """A one-word host name (a lab service such as "juice-shop"), taken only when you picked
    the template and typed it first. Free text never reads a lone word as a target."""
    words = text.split()
    first = _clean(words[0]) if words else ""
    if not first or not _HOSTNAME.match(first) or not any(c.isalpha() for c in first):
        return None
    # The whole line is the name ("metasploitable"), or the name looks like one (a dash or a
    # digit: "juice-shop port 3000"), so "my servers" or "the usual one" are not hosts.
    if len(words) > 1 and not any(c == "-" or c.isdigit() for c in first):
        return None
    if template_id == "network":
        value = host_value(first)
        return ParsedTarget("network", value, value, "network host", "network", True)
    if template_id in ("web_url", "api"):
        return url_target(f"http://{host_value(first)}", template_id)
    return None


# --- one typed value, for the Start prompt's feedback ----------------------------------------
TARGET_KINDS = ("URL", "IPV4", "IPV4_RANGE", "GIT_REPO", "LOCAL_PATH", "INVALID")
MAX_RANGE_ADDRESSES = 2 ** (32 - WIDEST_RANGE)  # 65,536 addresses: a /16
SUPPORTED_FORMATS = (
    "Supported: a URL (https://app.example.com), an IPv4 address (192.0.2.10), "
    "a CIDR range (10.0.0.0/24), a GitHub repo (https://github.com/acme/app) "
    "or a folder (~/code/app)."
)

_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]*):", re.IGNORECASE)
_NO_SLASH_SCHEMES = ("javascript", "file", "data", "mailto", "vbscript", "about")
# Recognized as repo hosts only so a non-GitHub repo is refused with GITHUB_ONLY.
_GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")
_IPV4_TOKEN = re.compile(r"\d+(?:\.\d+)+(?:/\d+)?")
_DASH_RANGE = re.compile(r"(\d+(?:\.\d+){3})-(\d+(?:\.\d+){3}|\d+)")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class TargetCheck:
    """A typed value read as a target: a kind from TARGET_KINDS, its value, or an error."""

    kind: str
    value: str = ""
    error: str = ""

    @property
    def valid(self) -> bool:
        return self.kind != "INVALID"


def _invalid(error: str) -> TargetCheck:
    return TargetCheck("INVALID", error=error)


def _shown(text: str) -> str:
    """The typed value, shortened to fit a one-line message."""
    return text if len(text) <= 40 else text[:39] + "…"


def _path_like(value: str) -> bool:
    return (
        value[0] in "/~\\"
        or bool(_DRIVE.match(value))
        or value in (".", "..")
        or value.startswith(("./", "../", ".\\", "..\\"))
    )


def looks_like_target(text: str) -> bool:
    """True when `text` is one value shaped like a target, not a question or a chat line."""
    value = text.strip()
    if not value or any(ch.isspace() for ch in value):
        return False
    if "://" in value or value.lower().startswith(("git@",) + _GIT_HOSTS) or _path_like(value):
        return True
    scheme = _SCHEME.match(value)
    if scheme and scheme.group(1).lower() in _NO_SLASH_SCHEMES:
        return True
    return bool(re.fullmatch(r"[\d./-]+", value)) and value.count(".") >= 2


def validate_target(text: str) -> TargetCheck:
    """What kind of target `text` is, normalized; or INVALID with a one-line reason.

    Format checks only, nothing touches the network; a local path must be an existing
    folder. This is feedback for the person typing: the backend's scope check decides.
    """
    value = text.strip()
    if not value:
        return _invalid(f"Type a target. {SUPPORTED_FORMATS}")
    if any(ch.isspace() for ch in value):
        return _invalid(f"A target is one value without spaces. {SUPPORTED_FORMATS}")
    for check in (_check_git, _check_url, _check_ipv4, _check_path):
        found = check(value)
        if found is not None:
            return found
    return _invalid(f'"{_shown(value)}" isn\'t a target. {SUPPORTED_FORMATS}')


def _check_git(value: str) -> Optional[TargetCheck]:
    """A repository ref, normalized to https://github.com/<owner>/<repo>; other hosts refused."""
    if not _is_repo_ref(value):
        return None  # an ordinary web URL, an address or a path
    try:
        return TargetCheck("GIT_REPO", github_repo(value))
    except StoreValidationError as exc:
        return _invalid(str(exc))


def _check_url(value: str) -> Optional[TargetCheck]:
    """http(s) URLs with a host; every other scheme is refused."""
    scheme = _SCHEME.match(value)
    if scheme is None or _DRIVE.match(value):
        return None
    name = scheme.group(1).lower()
    if "://" not in value and name not in _NO_SLASH_SCHEMES:
        return None  # e.g. "host:8080", no scheme
    if name not in ("http", "https"):
        return _invalid(
            f"{name}: links aren't supported — use http:// or https://, "
            "e.g. https://app.example.com"
        )
    try:
        base = url_target(value, "web_url").target_url
    except StoreValidationError as exc:
        return _invalid(f"{exc} Use a full URL, e.g. https://app.example.com")
    parts = _split(_clean(value))
    if parts is None:  # (url_target already refused it)
        return _invalid(f"{_shown(value)} isn't a valid URL.")
    rest = parts.path + (f"?{parts.query}" if parts.query else "")
    return TargetCheck("URL", base + rest)


def _check_ipv4(value: str) -> Optional[TargetCheck]:
    """An address, a CIDR range or a dash range."""
    dash = _DASH_RANGE.fullmatch(value)
    if dash:
        return _dash_range(dash.group(1), dash.group(2))
    if not _IPV4_TOKEN.fullmatch(value):
        return None
    try:
        normalized = ipv4(value)
    except StoreValidationError as exc:
        return _invalid(str(exc))
    return TargetCheck("IPV4_RANGE" if "/" in normalized else "IPV4", normalized)


def _dash_range(start_text: str, end_text: str) -> TargetCheck:
    """10.0.0.1-10.0.0.20, or 10.0.0.1-20 (the end replaces the last number)."""
    if "." not in end_text:
        end_text = start_text.rsplit(".", 1)[0] + "." + end_text
    try:
        start = ipaddress.IPv4Address(ipv4(start_text))
        end = ipaddress.IPv4Address(ipv4(end_text))
    except StoreValidationError as exc:
        return _invalid(str(exc))
    if start > end:
        return _invalid(
            f"{start}-{end} runs backwards — put the lower address first, e.g. 10.0.0.1-10.0.0.20"
        )
    count = int(end) - int(start) + 1
    if count > MAX_RANGE_ADDRESSES:
        return _invalid(
            f"{start}-{end} has {count:,} addresses — the limit is "
            f"{MAX_RANGE_ADDRESSES:,} (a /{WIDEST_RANGE})."
        )
    return TargetCheck("IPV4_RANGE", f"{start}-{end}")


def _check_path(value: str) -> Optional[TargetCheck]:
    """A local folder that exists (`~` is expanded)."""
    if not _path_like(value):
        return None
    path = os.path.abspath(os.path.expanduser(value))
    if not os.path.exists(path):
        return _invalid(f"{_shown(value)} doesn't exist — type a folder that does, e.g. ~/code/app")
    if not os.path.isdir(path):
        return _invalid(f"{_shown(value)} is a file — type its folder instead, e.g. ~/code/app")
    return TargetCheck("LOCAL_PATH", path)


__all__ = [
    "URL",
    "GIT_URL",
    "GIT_REF",
    "HOST",
    "IPV4_LIKE",
    "LOCAL_PATH",
    "ipv4",
    "host_value",
    "looks_api",
    "url_target",
    "network_target",
    "web_target",
    "api_target",
    "source_target",
    "github_repo",
    "GITHUB_ONLY",
    "FINDERS",
    "needs",
    "check_target",
    "TARGET_KINDS",
    "MAX_RANGE_ADDRESSES",
    "SUPPORTED_FORMATS",
    "TargetCheck",
    "looks_like_target",
    "validate_target",
    "DASH_RANGE_UNSUPPORTED",
]
