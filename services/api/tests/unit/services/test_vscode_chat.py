from types import SimpleNamespace
from uuid import uuid4

import pytest

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator
from reconix_api.models.enums import SessionStatus
from reconix_api.schemas.vscode_chat import FunctionCall, FunctionName
from reconix_api.services.chat_functions import FunctionContext
from reconix_api.services.vscode_chat import check_vscode_session, masked, run_call
from tests.fakes import build_fake_interfaces
from tests.unit.services.test_chat_chooser import FINDINGS


class FakeDb:
    """Only what session_repo.get needs: one session row by id."""

    def __init__(self, session=None):
        self.session = session

    def get(self, _model, session_id):
        return self.session if self.session and self.session.session_id == session_id else None


def session(interface="vscode", status=SessionStatus.ACTIVE):
    return SimpleNamespace(session_id=uuid4(), interface=interface, session_status=status)


def operator_of(row) -> Operator:
    return Operator(session_id=row.session_id, actor="tester")


def refused_code(db, operator, session_id) -> str:
    with pytest.raises(ApiError) as raised:
        check_vscode_session(db, operator, session_id)
    return f"{raised.value.status} {raised.value.code}"


def test_an_open_vscode_session_of_your_own_passes():
    row = session()
    check_vscode_session(FakeDb(row), operator_of(row), row.session_id)


def test_the_session_checks_refuse_in_order():
    row = session()
    assert refused_code(FakeDb(row), operator_of(row), uuid4()) == "403 NOT_YOUR_SESSION"
    assert refused_code(FakeDb(), operator_of(row), row.session_id) == "404 SESSION_NOT_FOUND"
    cli = session(interface="cli")
    assert refused_code(FakeDb(cli), operator_of(cli), cli.session_id) == "409 NOT_VSCODE_SESSION"
    closed = session(status=SessionStatus.CLOSED)
    assert refused_code(FakeDb(closed), operator_of(closed), closed.session_id) == (
        "409 SESSION_CLOSED"
    )


def context(audit_interfaces) -> FunctionContext:
    row = session()
    return FunctionContext(
        None, audit_interfaces, None, None, operator_of(row), row.session_id, lambda: FINDINGS
    )


@pytest.mark.parametrize(
    "call",
    [
        FunctionCall(name=FunctionName.EXPLAIN_FINDING, arguments={"finding_id": str(uuid4())}),
        FunctionCall(name=FunctionName.START_SCAN, arguments={"paths": ["../x"]}),
        FunctionCall(name=FunctionName.START_SCAN, arguments={"target": "/"}),
    ],
)
def test_a_refused_call_is_audited_and_goes_to_the_agent(call):
    interfaces, parts = build_fake_interfaces()

    assert run_call(context(interfaces), call) is None

    [event] = parts["audit"].events
    assert event.event_type == "CHAT_FUNCTION_REFUSED"
    assert event.details["function"] == call.name
    assert set(event.details) == {"function", "error"}  # never the arguments


def test_a_call_that_fits_writes_no_refusal():
    interfaces, parts = build_fake_interfaces()
    call = FunctionCall(name=FunctionName.LIST_FINDINGS, arguments={"severity": "HIGH"})

    assert run_call(context(interfaces), call).result.findings

    assert parts["audit"].events == []


def test_arguments_are_masked_value_by_value():
    def mask(text):
        return text.replace("ghp_secret", "[MASKED:token]"), text.count("ghp_secret")

    assert masked(mask, {"paths": ["src/ghp_secret.js"], "full": True}) == {
        "paths": ["src/[MASKED:token].js"],
        "full": True,
    }


def test_a_failing_function_is_audited_and_the_error_raised():
    interfaces, parts = build_fake_interfaces()
    call = FunctionCall(name=FunctionName.SUMMARIZE_FINDINGS)

    def broken():
        raise RuntimeError("database is down")

    failing = context(interfaces)
    object.__setattr__(failing, "load_findings", broken)
    with pytest.raises(RuntimeError):
        run_call(failing, call)

    [event] = parts["audit"].events
    assert event.event_type == "CHAT_FUNCTION_REFUSED"
    assert event.details == {"function": call.name, "error": "RuntimeError"}
