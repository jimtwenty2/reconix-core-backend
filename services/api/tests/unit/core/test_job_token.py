from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from reconix_api.core.job_token import InvalidJobToken, sign_job_token, verify_job_token

SECRET = "test-secret"
NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


def make_token(**overrides):
    values = {"tool_run_id": uuid4(), "action_hash": "abc", "secret": SECRET, "now": NOW}
    values.update(overrides)
    return sign_job_token(ttl_seconds=300, **values)


def test_a_signed_token_verifies():
    run_id = uuid4()
    claims = verify_job_token(make_token(tool_run_id=run_id), SECRET, NOW)
    assert claims.tool_run_id == run_id
    assert claims.action_hash == "abc"


def test_every_token_has_its_own_id():
    first = verify_job_token(make_token(), SECRET, NOW)
    second = verify_job_token(make_token(), SECRET, NOW)
    assert first.jti != second.jti


def test_expired_token_is_refused():
    with pytest.raises(InvalidJobToken, match="EXPIRED"):
        verify_job_token(make_token(), SECRET, NOW + timedelta(seconds=301))


def test_wrong_secret_is_refused():
    with pytest.raises(InvalidJobToken, match="BAD_SIGNATURE"):
        verify_job_token(make_token(), "other-secret", NOW)


def test_changed_payload_is_refused():
    payload, signature = make_token().split(".")
    tampered = payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1]
    with pytest.raises(InvalidJobToken):
        verify_job_token(f"{tampered}.{signature}", SECRET, NOW)


@pytest.mark.parametrize("token", ["", "no-dot", ".sig", "payload."])
def test_malformed_token_is_refused(token):
    with pytest.raises(InvalidJobToken):
        verify_job_token(token, SECRET, NOW)


def test_signing_needs_a_secret():
    with pytest.raises(ValueError):
        make_token(secret="")
