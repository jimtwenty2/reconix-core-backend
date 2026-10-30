"""The model settings for one agent run: the provider the run was started with, its key
decrypted.

Only ask_agent uses them, for the one call it makes, and only while the provider still has
the settings a person approved (`llm_providers.ensure_still_approved`). The key never goes into an
AgentRequest, the agent's state, a checkpoint, a log or a response.
"""

from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from reconix_ai.providers import ProviderConfig, reconix_provider
from reconix_ai.providers import ProviderType as AiProviderType
from reconix_api.core import provider_keys
from reconix_api.core.agent import ProviderFor
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import AgentRequest
from reconix_api.models import LlmProvider
from reconix_api.models.enums import ProviderType
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import llm_providers as provider_repo
from reconix_api.services import llm_providers


def make_provider_for(session_factory: sessionmaker[Session], settings: Settings) -> ProviderFor:
    def provider_for(request: AgentRequest) -> ProviderConfig:
        with session_factory() as db:
            run = agent_run_repo.get(db, request.agent_run_id)
            provider = provider_repo.get(db, run.llm_provider_id) if run else None
            if run is None or provider is None:
                raise ApiError(409, "RUN_NOT_FOUND", "The agent run has no saved provider.")
            check_request(request, provider, run.agent_run_id)
            llm_providers.ensure_still_approved(db, provider)
            return provider_config(settings, provider, run.model_name)

    return provider_for


def check_request(request: AgentRequest, provider: LlmProvider, run_id: UUID) -> None:
    """The request names the provider its run was started with, never another one."""
    if request.provider != provider.provider_type.value:
        raise ApiError(
            409,
            "PROVIDER_MISMATCH",
            "The request names another provider than its agent run.",
            {"agent_run_id": str(run_id)},
        )


def provider_config(settings: Settings, provider: LlmProvider, model_name: str) -> ProviderConfig:
    """The run's own model name (copied when the run started), the provider's address and
    its key. The built-in provider is always the RECONIX model on the local Ollama."""
    if provider.provider_type == ProviderType.RECONIX:
        return reconix_provider()
    api_key = None
    if provider.api_key_encrypted:
        api_key = provider_keys.decrypt(settings, provider.api_key_encrypted)
    return ProviderConfig(
        provider_type=AiProviderType(provider.provider_type.value),
        model_name=model_name,
        base_url=provider.base_url or None,
        api_key=api_key,
    )
