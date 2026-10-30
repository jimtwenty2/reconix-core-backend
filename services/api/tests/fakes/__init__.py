"""Fakes of the 6 shared functions. Use them until the real parts are merged."""

from reconix_api.core.interfaces import Interfaces
from tests.fakes.fake_ai import FakeAgent
from tests.fakes.fake_core import (
    OPERATOR_TOKEN,
    FakeAudit,
    FakeOperators,
    FakeScopes,
    fake_check,
    fake_mask_secrets,
)
from tests.fakes.fake_mcp import FakeMcp


def build_fake_interfaces() -> tuple[Interfaces, dict]:
    """Returns the fake Interfaces plus the fake objects, so tests can inspect them."""
    operators = FakeOperators()
    scopes = FakeScopes()
    audit = FakeAudit()
    agent = FakeAgent()
    mcp = FakeMcp()
    interfaces = Interfaces(
        get_operator=operators.get_operator,
        check=fake_check,
        get_approved_scope=scopes.get_approved_scope,
        write_audit=audit.write_audit,
        ask_agent=agent.ask_agent,
        call_tool=mcp.call_tool,
    )
    parts = {"operators": operators, "scopes": scopes, "audit": audit, "agent": agent, "mcp": mcp}
    return interfaces, parts


__all__ = [
    "OPERATOR_TOKEN",
    "FakeAgent",
    "FakeAudit",
    "FakeMcp",
    "FakeOperators",
    "FakeScopes",
    "build_fake_interfaces",
    "fake_check",
    "fake_mask_secrets",
]
