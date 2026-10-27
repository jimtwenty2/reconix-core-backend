"""Builds the real Interfaces for the running app.

A part that is not merged yet answers 503 NOT_READY instead of pretending to work.
Swap each stub for the real function on merge day.
"""

from typing import NoReturn

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Interfaces


def _not_ready(part: str):
    def stub(*_args, **_kwargs) -> NoReturn:
        raise ApiError(503, "NOT_READY", f"{part} is not merged yet.", {"part": part})

    async def async_stub(*_args, **_kwargs) -> NoReturn:
        stub()

    return stub, async_stub


def build_interfaces() -> Interfaces:
    get_operator, _ = _not_ready("get_operator")
    check, _ = _not_ready("check")
    get_approved_scope, _ = _not_ready("get_approved_scope")
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
