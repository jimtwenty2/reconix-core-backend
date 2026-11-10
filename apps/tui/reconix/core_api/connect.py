"""The Core API session this app run uses.

One session per app run, opened on first use. Its token stays in this module's memory.
If the API restarts (the token is unknown, 401), a new session is opened once and the
caller's sync starts over (`on_new_session` hooks clear what belonged to the old one).

The provider the API uses for the model is chosen in /provider and kept by the API itself
(`store.providers`, `/api/v1/llm-providers`); this module only carries the session.
"""

import getpass
import socket
from typing import Any, Callable, Dict, List

from .client import CoreApiError, call

_session: Dict[str, str] = {"token": "", "session_id": ""}
on_new_session: List[Callable[[], None]] = []


def session_id() -> str:
    """This app's session on the API, opened on first use."""
    if not _session["token"]:
        _open_session()
    return _session["session_id"]


def request(method: str, path: str, body: Any = None) -> Any:
    """A call as this app's session. A session the API no longer knows (it restarted) is
    opened again once; the call is not repeated, because the caller's ids are stale."""
    session_id()
    try:
        return call(method, path, body, _session["token"])
    except CoreApiError as exc:
        if exc.status == 401:
            reset()
        raise


def reset() -> None:
    """Forget the session (and everything synced to it)."""
    _session.update(token="", session_id="")
    for hook in on_new_session:
        hook()


def _operator() -> str:
    """This computer's user@host, the name the API records for this session."""
    try:
        return f"{getpass.getuser()}@{socket.gethostname()}"[:100]
    except Exception:  # noqa: BLE001 - a nameless environment: let the API use its own
        return ""


def _open_session() -> None:
    body: Dict[str, Any] = {"interface": "cli"}
    operator = _operator()
    if operator:
        body["operator"] = operator
    opened = call("POST", "/sessions", body)
    _session.update(token=opened["token"], session_id=opened["session_id"])
