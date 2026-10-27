"""One-time job tokens: the backend signs one per tool run; the Kali MCP server checks it.

Format: <payload>.<signature>, both base64url. The payload is JSON with a random `jti`,
the tool run id and an expiry. The Kali side refuses a bad signature, an expired token
and any `jti` it has already seen (single use).
"""

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta
from uuid import UUID

from pydantic import BaseModel


class JobClaims(BaseModel):
    jti: str
    tool_run_id: UUID
    action_hash: str
    expires_at: datetime


class InvalidJobToken(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _signature(payload: str, secret: str) -> str:
    return _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())


def sign_job_token(
    tool_run_id: UUID, action_hash: str, secret: str, now: datetime, ttl_seconds: int
) -> str:
    if not secret:
        raise ValueError("RECONIX_JOB_TOKEN_SECRET is not set")
    claims = JobClaims(
        jti=secrets.token_urlsafe(16),
        tool_run_id=tool_run_id,
        action_hash=action_hash,
        expires_at=now + timedelta(seconds=ttl_seconds),
    )
    payload = _b64(claims.model_dump_json().encode())
    return f"{payload}.{_signature(payload, secret)}"


def verify_job_token(token: str, secret: str, now: datetime) -> JobClaims:
    """Checks signature and expiry. The caller must also refuse a `jti` seen before."""
    payload, _, signature = token.partition(".")
    if not payload or not signature:
        raise InvalidJobToken("MALFORMED")
    if not hmac.compare_digest(signature, _signature(payload, secret)):
        raise InvalidJobToken("BAD_SIGNATURE")
    claims = JobClaims.model_validate(json.loads(_unb64(payload)))
    if now >= claims.expires_at:
        raise InvalidJobToken("EXPIRED")
    return claims
