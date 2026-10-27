from uuid import uuid4

import pytest

from reconix_api.core.interfaces import Operator, Role
from reconix_api.core.session_tokens import SessionTokens


def make_operator() -> Operator:
    return Operator(session_id=uuid4(), role=Role.OPERATOR, actor="operator")


def test_issued_token_finds_the_operator():
    tokens = SessionTokens()
    operator = make_operator()
    assert tokens.get_operator(tokens.issue(operator)) == operator


def test_tokens_are_random_and_long():
    tokens = SessionTokens()
    operator = make_operator()
    first, second = tokens.issue(operator), tokens.issue(operator)
    assert first != second
    assert len(first) >= 40


def test_unknown_token_is_refused():
    with pytest.raises(PermissionError):
        SessionTokens().get_operator("nope")


def test_revoke_signs_the_session_out():
    tokens = SessionTokens()
    operator = make_operator()
    token = tokens.issue(operator)
    tokens.revoke_session(operator.session_id)
    with pytest.raises(PermissionError):
        tokens.get_operator(token)
