"""Kali MCP reachability — the seam the TUI reads for the session bar's kali chip.

Static today: the status is UNKNOWN and the host None until a future wire-backend task
fills it from the Core API. The store only ever holds and hands back the value; no network
call lives here (the apps never reach Kali themselves — rule S7).
"""

from typing import Optional

from . import lists
from .errors import StoreValidationError

STATUSES = ("REACHABLE", "UNREACHABLE", "UNKNOWN")


def kali_status() -> str:
    """Whether the backend's Kali MCP container is reachable: one of STATUSES."""
    return lists.KALI["status"]


def kali_host() -> Optional[str]:
    """A short host string for the Kali MCP container, or None when unknown."""
    return lists.KALI["host"]


def set_kali_status(status: str, host: Optional[str] = None) -> None:
    """The seam that records Kali reachability (from the Core API, or a future wiring)."""
    if status not in STATUSES:
        raise StoreValidationError(f"Unknown Kali status: {status!r}.")
    host = host.strip() if host and host.strip() else None
    lists.KALI.update(status=status, host=host)


def refresh_kali() -> None:
    """Ask the Core API whether the Kali MCP container is reachable and record it.

    Blocks on the network, so a caller runs it off the UI thread. It never raises into the
    UI: if the Core API is down (or refuses), we don't know Kali's state, so the status
    falls back to UNKNOWN and the app keeps running offline.
    """
    from .. import core_api  # lazy: avoid a store ↔ core_api import cycle

    try:
        answer = core_api.fetch_kali_status()
    except core_api.CoreApiError:
        set_kali_status("UNKNOWN", None)
        return
    status = "REACHABLE" if answer.get("connected") else "UNREACHABLE"
    set_kali_status(status, answer.get("host"))
