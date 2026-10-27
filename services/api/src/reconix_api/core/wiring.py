"""Builds the real Interfaces for the running app.

A part that is not merged yet answers 503 NOT_READY instead of pretending to work.
Swap each stub for the real function on merge day.
"""

from typing import NoReturn

from sqlalchemy.orm import Session, sessionmaker

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Interfaces
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.services.scopes import make_get_approved_scope


def _not_ready(part: str):
    def stub(*_args, **_kwargs) -> NoReturn:
        raise ApiError(503, "NOT_READY", f"{part} is not merged yet.", {"part": part})

    async def async_stub(*_args, **_kwargs) -> NoReturn:
        stub()

    return stub, async_stub


def build_interfaces(
    session_tokens: SessionTokens | None = None,
    session_factory: sessionmaker[Session] | None = None,
) -> Interfaces:
    """The API's own two parts are real when their inputs are given."""
    get_operator, _ = _not_ready("get_operator")
    if session_tokens is not None:
        get_operator = session_tokens.get_operator
    get_approved_scope, _ = _not_ready("get_approved_scope")
    if session_factory is not None:
        get_approved_scope = make_get_approved_scope(session_factory)
    check, _ = _not_ready("check")
    write_audit, _ = _not_ready("write_audit")
    _, ask_agent = _not_ready("ask_agent")
    _, call_tool = _not_ready("call_tool")
    return Interfaces(
        get_operator=get_operator,
        check=check,
        get_approved_scope=get_approved_scope,
        write_audit=write_audit,
        ask_agent=ask_agent,
        call_tool=call_tool,
    )
