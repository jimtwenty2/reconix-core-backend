import uuid

import pytest

from reconix_api.core.errors import ApiError
from reconix_api.models import Approval, LlmProvider
from reconix_api.models.enums import ProviderType
from reconix_api.services.llm_providers import (
    ACTIVATE,
    activation_hash,
    check_settings,
    is_activation,
    is_local,
)


def code_of(call) -> str:
    with pytest.raises(ApiError) as error:
        call()
    return error.value.code


@pytest.mark.parametrize("provider_type", ["OPENAI", "ANTHROPIC", "DEEPSEEK"])
def test_a_cloud_service_needs_a_key(provider_type):
    assert code_of(lambda: check_settings(provider_type, None, has_key=False)) == (
        "PROVIDER_KEY_MISSING"
    )
    check_settings(provider_type, None, has_key=True)


def test_an_openai_compatible_server_needs_its_address():
    compatible = ProviderType.OPENAI_API_COMPATIBLE
    assert code_of(lambda: check_settings(compatible, None, has_key=True)) == (
        "PROVIDER_URL_MISSING"
    )
    check_settings(compatible, "https://llm.example.com", has_key=False)


def test_ollama_needs_neither_a_key_nor_an_address():
    check_settings(ProviderType.OLLAMA, None, has_key=False)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://llm.example.com",  # plain http off this computer
        "https://user:pass@llm.example.com",  # a user name and password
        "http://169.254.169.254",  # cloud metadata
        "https://llm.example.com/?key=1",  # a query
        "ftp://llm.example.com",
    ],
)
def test_an_unsafe_address_is_refused(base_url):
    assert code_of(lambda: check_settings(ProviderType.OPENAI, base_url, has_key=True)) == (
        "PROVIDER_URL_NOT_ALLOWED"
    )


@pytest.mark.parametrize(
    ("provider_type", "base_url", "local"),
    [
        (ProviderType.RECONIX, None, True),
        (ProviderType.OLLAMA, None, True),  # the local Ollama
        (ProviderType.OLLAMA, "http://127.0.0.1:11434", True),
        (ProviderType.OLLAMA, "http://ollama:11434", True),  # the compose service
        (ProviderType.OLLAMA, "https://gpu.example.com", False),
        (ProviderType.OPENAI_API_COMPATIBLE, "http://localhost:8080", True),
        (ProviderType.OPENAI_API_COMPATIBLE, "https://llm.example.com", False),
        (ProviderType.OPENAI, None, False),  # the cloud service's own address
        (ProviderType.ANTHROPIC, None, False),
        (ProviderType.DEEPSEEK, None, False),
    ],
)
def test_which_providers_run_on_this_computer(provider_type, base_url, local):
    assert is_local(provider_type, base_url) is local


def cloud_provider(**overrides) -> LlmProvider:
    values = {
        "llm_provider_id": uuid.UUID(int=1),
        "provider_type": ProviderType.OPENAI,
        "display_name": "OpenAI",
        "base_url": None,
        "model_name": "gpt-4o",
        "api_key_encrypted": b"encrypted-key-1",
        "api_key_last4": "abcd",
    }
    values.update(overrides)
    return LlmProvider(**values)


@pytest.mark.parametrize(
    "change",
    [
        {"base_url": "https://other.example.com"},
        {"model_name": "gpt-4o-mini"},
        # A new key with the same last 4 characters still needs a new approval.
        {"api_key_encrypted": b"encrypted-key-2"},
    ],
)
def test_the_activation_hash_changes_with_any_setting(change):
    assert activation_hash(cloud_provider(**change)) != activation_hash(cloud_provider())


def test_only_a_provider_change_is_an_activation():
    def approval(kind: str, change: str | None) -> Approval:
        return Approval(kind=kind, config_change={"change": change} if change else None)

    assert is_activation(approval("configuration", ACTIVATE))
    assert not is_activation(approval("configuration", "SET_LIMIT"))
    assert not is_activation(approval("configuration", None))
    assert not is_activation(approval("review", ACTIVATE))
