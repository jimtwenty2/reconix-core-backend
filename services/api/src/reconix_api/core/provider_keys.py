"""AI provider API keys: encrypted with Fernet (RECONIX_FERNET_KEY) before they are saved.

Only the last 4 characters are ever shown. The key itself never leaves this module in
clear, except to the model call that needs it.
"""

from cryptography.fernet import Fernet, InvalidToken

from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError


def encrypt(settings: Settings, api_key: str) -> bytes:
    return fernet(settings).encrypt(api_key.encode())


def decrypt(settings: Settings, token: bytes) -> str:
    try:
        return fernet(settings).decrypt(token).decode()
    except InvalidToken:
        raise ApiError(
            409,
            "PROVIDER_KEY_UNREADABLE",
            "The saved API key cannot be read with RECONIX_FERNET_KEY. Enter the key again.",
        ) from None


def last4(api_key: str) -> str:
    return api_key[-4:]


def fernet(settings: Settings) -> Fernet:
    key = settings.fernet_key.get_secret_value()
    if not key:
        raise ApiError(503, "FERNET_KEY_MISSING", "Set RECONIX_FERNET_KEY to save API keys.")
    try:
        return Fernet(key)
    except ValueError:
        raise ApiError(
            503, "FERNET_KEY_INVALID", "RECONIX_FERNET_KEY is not a valid Fernet key."
        ) from None
