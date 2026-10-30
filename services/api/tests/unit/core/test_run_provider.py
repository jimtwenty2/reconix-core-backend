from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

from reconix_ai.providers import ProviderType as AiProviderType
from reconix_ai.providers import reconix_provider
from reconix_api.core import provider_keys
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import AgentRequest, AgentTask, ApprovedScope
from reconix_api.core.run_provider import check_request, provider_config
from reconix_api.models import LlmProvider
from reconix_api.models.enums import ProviderType

FAKE_API_KEY = "sk-fake-test-key-0000-abcd"  # noqa: S105
SETTINGS = Settings(fernet_key=Fernet.generate_key().decode())


def provider(provider_type: ProviderType, **values) -> LlmProvider:
    return LlmProvider(
        provider_type=provider_type,
        display_name="test",
        model_name=values.pop("model_name", "saved-model"),
        **values,
    )


def request_for(provider_name: str) -> AgentRequest:
    assessment_id = uuid4()
    return AgentRequest(
        task=AgentTask.PLAN,
        assessment_id=assessment_id,
        agent_run_id=uuid4(),
        scope=ApprovedScope(assessment_id=assessment_id),
        provider=provider_name,
    )


def test_the_built_in_provider_is_the_local_reconix_model():
    config = provider_config(SETTINGS, provider(ProviderType.RECONIX), "reconix")

    assert config == reconix_provider()


def test_another_provider_gets_its_address_its_key_and_the_runs_model():
    row = provider(
        ProviderType.OPENAI_API_COMPATIBLE,
        base_url="https://llm.example.test/v1",
        api_key_encrypted=provider_keys.encrypt(SETTINGS, FAKE_API_KEY),
    )

    config = provider_config(SETTINGS, row, "model-the-run-started-with")

    assert config.provider_type == AiProviderType.OPENAI_API_COMPATIBLE
    assert config.model_name == "model-the-run-started-with"
    assert config.base_url == "https://llm.example.test/v1"
    assert config.api_key == FAKE_API_KEY
    assert FAKE_API_KEY not in repr(config)


def test_a_provider_without_a_key_sends_none():
    config = provider_config(SETTINGS, provider(ProviderType.OLLAMA, base_url=""), "llama3.2")

    assert (config.api_key, config.base_url) == (None, None)


def test_a_request_for_another_provider_than_its_run_is_refused():
    with pytest.raises(ApiError) as error:
        check_request(request_for("OPENAI"), provider(ProviderType.OLLAMA), uuid4())

    assert (error.value.status, error.value.code) == (409, "PROVIDER_MISMATCH")
