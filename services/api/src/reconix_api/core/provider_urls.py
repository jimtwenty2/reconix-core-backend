"""AI provider addresses, as the API checks them before it saves or activates a provider.

The safety rule is the AI Service's own (reconix_ai.providers.base_url, AI provider safety
owner: Pojim), so an address that saves is one the model call accepts. "On this computer"
is decided here, more strictly than the call does: only localhost and loopback addresses
count, never a name such as "ollama" that a DNS search domain could send elsewhere.
"""

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from reconix_ai.providers.base_url import BaseUrlError, check_base_url
from reconix_ai.providers.settings import ollama_url
from reconix_api.core.errors import ApiError


def check(base_url: str) -> None:
    """422 PROVIDER_URL_NOT_ALLOWED unless the address is safe and written plainly. The
    message never repeats the address."""
    try:
        plain = _plain_form(base_url)
        check_base_url(base_url)
    except BaseUrlError as error:
        raise _not_allowed(str(error)) from None
    except ValueError:  # e.g. a broken [IPv6] host or a port outside 0-65535
        raise _not_allowed("The address is not a valid URL.") from None
    if not plain:
        raise _not_allowed("Write the address plainly: no spaces, tabs or port 0.")


def is_local_address(url: str) -> bool:
    """localhost or a loopback IP only."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def default_ollama_url() -> str:
    """Where the built-in RECONIX model and an Ollama provider with no address are
    called: RECONIX_OLLAMA_URL, or Ollama on this computer."""
    return ollama_url()


def _plain_form(base_url: str) -> bool:
    """False for text that urlsplit() would quietly change, such as a tab or a leading
    space, so what is approved is exactly what gets called."""
    parts = urlsplit(base_url)
    if parts.port == 0:  # .port raises ValueError outside 0-65535
        return False
    return urlunsplit(parts) == base_url


def _not_allowed(message: str) -> ApiError:
    return ApiError(422, "PROVIDER_URL_NOT_ALLOWED", message)
