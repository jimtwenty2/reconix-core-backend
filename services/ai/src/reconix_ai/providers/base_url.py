"""Which model addresses a call may go to.

A strict stand-in until the AI provider safety check (owner: Pojim) lands;
swap check_base_url() for it then. Plain HTTP only to this computer or the
compose service, HTTPS anywhere else, and nothing that could steer the request
to another path: no user:password, no query, no fragment, and no path except
"/v1", where OpenAI-compatible servers answer.
"""

import ipaddress
from urllib.parse import urlsplit

# Service names inside deploy/docker-compose.yml, on the private backend network.
LOCAL_HOST_NAMES = {"localhost", "ollama", "qdrant"}
METADATA_HOST_NAMES = {"metadata.google.internal", "metadata"}
# AWS's IPv6 metadata address is not link-local, so it is named here.
METADATA_ADDRESSES = {ipaddress.ip_address("fd00:ec2::254")}


class BaseUrlError(ValueError):
    """The address is not allowed. The message never repeats the address."""


def check_base_url(url: str) -> None:
    """Raise BaseUrlError unless the model address is safe to call."""
    if any(char.isspace() or not char.isprintable() for char in url):
        # urlsplit() would drop a tab or newline, but the raw text is what gets called.
        raise BaseUrlError("The address must not contain spaces or control characters.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BaseUrlError("The address must start with http:// or https://.")
    if parts.username is not None or parts.password is not None:
        raise BaseUrlError("The address must not contain a user name or password.")
    if parts.path.rstrip("/") not in ("", "/v1") or parts.query or parts.fragment:
        raise BaseUrlError("The address must not have a path (except /v1), query or fragment.")
    host = (parts.hostname or "").rstrip(".")  # "metadata." is "metadata"
    if not host:
        raise BaseUrlError("The address has no host.")
    if is_metadata(host):
        raise BaseUrlError("Cloud metadata and link-local addresses are not allowed.")
    if parts.scheme == "http" and not is_local(host):
        raise BaseUrlError("Plain http is only allowed to this computer; use https.")


def is_local(host: str) -> bool:
    if host.lower() in LOCAL_HOST_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_metadata(host: str) -> bool:
    if host.lower() in METADATA_HOST_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host)
        return address.is_link_local or address in METADATA_ADDRESSES
    except ValueError:
        return False
