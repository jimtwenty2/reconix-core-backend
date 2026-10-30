import pytest
from cryptography.fernet import Fernet

from reconix_api.core import provider_keys
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError

FAKE_API_KEY = "sk-fake-test-key-0000-abcd"  # noqa: S105


def settings_with(fernet_key: str) -> Settings:
    return Settings(fernet_key=fernet_key)


def test_a_key_is_encrypted_and_reads_back():
    settings = settings_with(Fernet.generate_key().decode())

    token = provider_keys.encrypt(settings, FAKE_API_KEY)

    assert FAKE_API_KEY.encode() not in token
    assert provider_keys.decrypt(settings, token) == FAKE_API_KEY


def test_only_the_last_4_characters_are_kept_for_display():
    assert provider_keys.last4(FAKE_API_KEY) == "abcd"


def test_no_fernet_key_refuses_to_save_a_key():
    with pytest.raises(ApiError) as error:
        provider_keys.encrypt(settings_with(""), FAKE_API_KEY)
    assert (error.value.status, error.value.code) == (503, "FERNET_KEY_MISSING")


def test_a_wrong_fernet_key_is_refused():
    with pytest.raises(ApiError) as error:
        provider_keys.encrypt(settings_with("not-a-fernet-key"), FAKE_API_KEY)
    assert error.value.code == "FERNET_KEY_INVALID"


def test_a_key_saved_with_another_fernet_key_cannot_be_read():
    token = provider_keys.encrypt(settings_with(Fernet.generate_key().decode()), FAKE_API_KEY)

    with pytest.raises(ApiError) as error:
        provider_keys.decrypt(settings_with(Fernet.generate_key().decode()), token)
    assert error.value.code == "PROVIDER_KEY_UNREADABLE"
    assert FAKE_API_KEY not in error.value.message
