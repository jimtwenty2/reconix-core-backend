"""Session tokens, kept in memory only (never in the database or logs).

This is the real get_operator. A restart of the API signs everyone out, on purpose.
Week 2: `/web` will issue viewer tokens through the same store.
"""

import secrets
from uuid import UUID

from reconix_api.core.interfaces import Operator


class SessionTokens:
    def __init__(self) -> None:
        self._operators: dict[str, Operator] = {}

    def issue(self, operator: Operator) -> str:
        token = secrets.token_urlsafe(32)
        self._operators[token] = operator
        return token

    def get_operator(self, token: str) -> Operator:
        """Matches the GetOperator interface. Raises PermissionError for an unknown token."""
        operator = self._operators.get(token)
        if operator is None:
            raise PermissionError("UNKNOWN_TOKEN")
        return operator

    def revoke_session(self, session_id: UUID) -> None:
        self._operators = {
            token: operator
            for token, operator in self._operators.items()
            if operator.session_id != session_id
        }
