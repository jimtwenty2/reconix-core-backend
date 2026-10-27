"""Which model addresses a call may go to.

A strict stand-in until the AI provider safety check (owner: Pojim) lands;
swap check_base_url() for it then. Plain HTTP only to this computer or the
compose service, HTTPS anywhere else, and nothing that could steer the request
to another path: no user:password, no path, no query, no fragment.
"""

import ipaddress
from urllib.parse import urlsplit

# The Ollama service name inside deploy/docker-compose.yml.
LOCAL_HOST_NAMES = {"localhost", "ollama"}
METADATA_HOST_NAMES = {"metadata.google.internal", "metadata"}


class BaseUrlError(ValueError):
    """The address is not allowed. The message never repeats the address."""


def check_base_url(url: str) -> None:
    """Raise BaseUrlError unless the model address is safe to call."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BaseUrlError("The address must start with http:// or https://.")
    if parts.username is not None or parts.password is not None:
        raise BaseUrlError("The address must not contain a user name or password.")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise BaseUrlError("The address must not have a path, query or fragment.")
    host = parts.hostname or ""
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
        return ipaddress.ip_address(host).is_link_local
    except ValueError:
        return False
