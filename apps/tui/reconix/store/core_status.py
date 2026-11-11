"""Whether the Core API is reachable right now, for the header to show.

The app polls `core_api.client.health()` in the background and records the result here.
`None` means "not checked yet"; the header shows that as an in-between state rather than
claiming the API is up or down before the first check lands.
"""

from typing import List, Optional

# A one-item list so this module's state is mutable and shared, like the other store state.
_ONLINE: List[Optional[bool]] = [None]


def api_online() -> Optional[bool]:
    """True up, False down, None not checked yet."""
    return _ONLINE[0]


def set_api_online(online: Optional[bool]) -> None:
    _ONLINE[0] = online


def reset() -> None:
    """Forget the last check (a fresh session re-checks)."""
    _ONLINE[0] = None
