"""Session tokens and web sign-in codes, kept in memory only (never in the database or logs).

This is the real get_operator. A restart of the API signs everyone out, on purpose.

`/web` in the terminal app asks for a sign-in code and puts it in the link it prints. The
web server trades the code for its own session token, so the token itself never sits in
a URL. A code works once, only for a short time, and only while the session that asked
for it is open. The code is not a second lock: POST /sessions is open to this computer
anyway. It only keeps the long-lived token out of links.

Routes run on several threads at once, so every read and change holds the lock.
"""

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from reconix_api.core.interfaces import Operator

SIGN_IN_CODE_TTL = timedelta(minutes=2)


@dataclass(frozen=True)
class SignInCode:
    issued_by: UUID  # the session that asked for it
    expires_at: datetime
    actor: str = ""  # who asked for it: the web session gets the same name


class SessionTokens:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._operators: dict[str, Operator] = {}
        self._sign_in_codes: dict[str, SignInCode] = {}

    def issue(self, operator: Operator) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._operators[token] = operator
        return token

    def get_operator(self, token: str) -> Operator:
        """Matches the GetOperator interface. Raises PermissionError for an unknown token."""
        with self._lock:
            operator = self._operators.get(token)
        if operator is None:
            raise PermissionError("UNKNOWN_TOKEN")
        return operator

    def revoke_session(self, session_id: UUID) -> None:
        """Signs the session out, and its unused sign-in codes stop working too."""
        with self._lock:
            self._operators = {
                token: operator
                for token, operator in self._operators.items()
                if operator.session_id != session_id
            }
            self._sign_in_codes = {
                code: entry
                for code, entry in self._sign_in_codes.items()
                if entry.issued_by != session_id
            }

    def issue_sign_in_code(self, operator: Operator, now: datetime) -> tuple[str, datetime]:
        """A new one-time code for this person's session, and when it stops working."""
        code = secrets.token_urlsafe(32)
        expires_at = now + SIGN_IN_CODE_TTL
        with self._lock:
            self._sign_in_codes = {
                old: entry for old, entry in self._sign_in_codes.items() if entry.expires_at > now
            }
            self._sign_in_codes[code] = SignInCode(operator.session_id, expires_at, operator.actor)
        return code, expires_at

    def use_sign_in_code(self, code: str, now: datetime) -> SignInCode:
        """Uses up the code and returns who asked for it (their session and name). Raises
        PermissionError if the code is unknown, used, expired, or its session was closed."""
        with self._lock:
            entry = self._sign_in_codes.pop(code, None)
        if entry is None or now >= entry.expires_at:
            raise PermissionError("INVALID_SIGN_IN_CODE")
        return entry
