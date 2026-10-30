from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from reconix_api.core.interfaces import Operator
from reconix_api.core.session_tokens import SessionTokens


def make_operator() -> Operator:
    return Operator(session_id=uuid4(), actor="operator")


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


NOW = datetime(2026, 10, 30, 20, 0, tzinfo=UTC)


def test_a_sign_in_code_works_once():
    tokens = SessionTokens()
    code, _ = tokens.issue_sign_in_code(make_operator(), NOW)
    tokens.use_sign_in_code(code, NOW)
    with pytest.raises(PermissionError):
        tokens.use_sign_in_code(code, NOW)


def test_a_sign_in_code_expires_after_2_minutes():
    tokens = SessionTokens()
    code, expires_at = tokens.issue_sign_in_code(make_operator(), NOW)
    assert expires_at == NOW + timedelta(minutes=2)
    with pytest.raises(PermissionError):
        tokens.use_sign_in_code(code, expires_at)


def test_an_unknown_sign_in_code_is_refused():
    with pytest.raises(PermissionError):
        SessionTokens().use_sign_in_code("nope", NOW)


def test_a_sign_in_code_is_not_a_session_token():
    tokens = SessionTokens()
    code, _ = tokens.issue_sign_in_code(make_operator(), NOW)
    with pytest.raises(PermissionError):
        tokens.get_operator(code)


def test_sign_in_codes_are_random_and_long():
    tokens = SessionTokens()
    first, _ = tokens.issue_sign_in_code(make_operator(), NOW)
    second, _ = tokens.issue_sign_in_code(make_operator(), NOW)
    assert first != second
    assert len(first) >= 40


def test_a_sign_in_code_names_the_session_that_asked():
    tokens = SessionTokens()
    operator = make_operator()
    code, _ = tokens.issue_sign_in_code(operator, NOW)
    assert tokens.use_sign_in_code(code, NOW) == operator.session_id


def test_closing_the_session_cancels_its_sign_in_codes():
    tokens = SessionTokens()
    operator, other = make_operator(), make_operator()
    code, _ = tokens.issue_sign_in_code(operator, NOW)
    kept, _ = tokens.issue_sign_in_code(other, NOW)
    tokens.revoke_session(operator.session_id)
    with pytest.raises(PermissionError):
        tokens.use_sign_in_code(code, NOW)
    assert tokens.use_sign_in_code(kept, NOW) == other.session_id
