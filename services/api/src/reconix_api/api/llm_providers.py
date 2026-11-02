"""AI providers: list, add, read, edit, remove, and make one active."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.llm_providers import (
    LlmProviderActivation,
    LlmProviderIn,
    LlmProviderModelsOut,
    LlmProviderOut,
    LlmProviderTestOut,
    LlmProviderUpdate,
)
from reconix_api.services import decisions, llm_providers

router = APIRouter(prefix="/llm-providers", tags=["llm providers"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.get("")
def list_providers(db: Db, _: CurrentOperator) -> list[LlmProviderOut]:
    """Lists the AI providers, oldest first. The built-in RECONIX provider is always there."""
    return llm_providers.list_providers(db)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_provider(
    body: LlmProviderIn,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> LlmProviderOut:
    """Adds an AI provider. It is saved inactive. Its API key is encrypted and never shown again;
    you only see its last 4 characters. OPENAI, ANTHROPIC and DEEPSEEK need a key, and
    OPENAI_API_COMPATIBLE needs a base_url."""
    return llm_providers.create_provider(db, interfaces.write_audit, mask, settings, operator, body)


@router.get("/{llm_provider_id}")
def read_provider(llm_provider_id: UUID, db: Db, _: CurrentOperator) -> LlmProviderOut:
    """Returns one AI provider. For safety, its API key is never shown in full: only its last 4
    characters. Returns 404 LLM_PROVIDER_NOT_FOUND if there is no provider with this id."""
    return llm_providers.read_provider(db, llm_provider_id)


@router.patch("/{llm_provider_id}")
def update_provider(
    llm_provider_id: UUID,
    body: LlmProviderUpdate,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> LlmProviderOut:
    """Changes a provider. Only the fields you send change. The built-in provider and the active
    provider cannot be changed."""
    return llm_providers.update_provider(
        db, interfaces.write_audit, mask, settings, operator, llm_provider_id, body
    )


@router.delete("/{llm_provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(
    llm_provider_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> None:
    """Deletes a provider. You cannot delete the built-in provider, the active provider, or a
    provider that agent runs have used."""
    llm_providers.delete_provider(db, interfaces.write_audit, operator, llm_provider_id)


@router.post("/{llm_provider_id}/activate")
def activate_provider(
    llm_provider_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> LlmProviderActivation:
    """Makes a provider the active one. A provider on this computer becomes active at once. Any
    other provider answers with a `configuration` approval, and becomes active once a person
    approves it."""
    ttl_minutes = settings.approval_ttl_minutes
    provider, approval = llm_providers.activate(
        db, interfaces.write_audit, operator, llm_provider_id, ttl_minutes
    )
    approval_out = decisions.approval_out(approval, ttl_minutes) if approval else None
    return LlmProviderActivation(llm_provider=provider, approval=approval_out)


@router.post("/{llm_provider_id}/test")
async def test_provider(
    llm_provider_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> LlmProviderTestOut:
    """Sends the model one fixed prompt that contains no Reconix data, and tells you whether it
    answered and how fast. It changes nothing."""
    return await llm_providers.test_provider(
        db, interfaces.write_audit, settings, operator, llm_provider_id
    )


@router.get("/{llm_provider_id}/models")
async def list_models(llm_provider_id: UUID, db: Db, _: CurrentOperator) -> LlmProviderModelsOut:
    """Lists the models that a RECONIX or OLLAMA provider's Ollama has on this computer. Cloud
    providers return 422 MODEL_LIST_NOT_SUPPORTED."""
    return await llm_providers.list_models(db, llm_provider_id)
