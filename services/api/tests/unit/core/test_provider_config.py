from cryptography.fernet import Fernet

from reconix_ai.providers import ProviderType as AiProviderType
from reconix_ai.providers import reconix_provider
from reconix_api.core import provider_keys
from reconix_api.core.agent import provider_config
from reconix_api.core.config import Settings
from reconix_api.models import LlmProvider
from reconix_api.models.enums import ProviderType

FAKE_API_KEY = "sk-fake-test-key-0000-abcd"  # noqa: S105
SETTINGS = Settings(provider_encryption_key=Fernet.generate_key().decode())


def row(provider_type: ProviderType, **values) -> LlmProvider:
    return LlmProvider(provider_type=provider_type, model_name="saved-model", **values)


def test_the_built_in_provider_is_the_local_reconix_model():
    assert provider_config(SETTINGS, row(ProviderType.RECONIX), "reconix") == reconix_provider()


def test_a_cloud_provider_gets_its_decrypted_key_and_the_runs_model():
    encrypted = provider_keys.encrypt(SETTINGS, FAKE_API_KEY)
    openai = row(ProviderType.OPENAI, api_key_encrypted=encrypted)

    config = provider_config(SETTINGS, openai, "gpt-4o")

    assert config.provider_type == AiProviderType.OPENAI
    assert config.model_name == "gpt-4o"  # the run's copy, even if the row changed since
    assert config.api_key == FAKE_API_KEY
    assert FAKE_API_KEY not in repr(config)


def test_a_provider_without_a_key_keeps_its_address():
    ollama = row(ProviderType.OLLAMA, base_url="http://127.0.0.1:11434")

    config = provider_config(SETTINGS, ollama, "llama3.1:8b")

    assert (config.base_url, config.api_key) == ("http://127.0.0.1:11434", None)
