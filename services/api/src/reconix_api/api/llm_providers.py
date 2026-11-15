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
    """Retrieves the LLM providers, oldest first.

    Business Rules:
    - The built-in RECONIX provider is there until it is deleted; it can be added back.

    Security:
    - Requires a valid session token.
    """
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
    """Adds an LLM provider. It is saved inactive.

    Business Rules:
    - OPENAI, ANTHROPIC, and DEEPSEEK require an API key; OPENAI_API_COMPATIBLE requires a base_url.
    - Another model of a saved provider can reuse its key: send `copy_key_from` (that
      provider's id) instead of `api_key`. Only from the same provider_type at the same
      base_url (422 KEY_NOT_COPYABLE); not together with `api_key` (422 KEY_GIVEN_TWICE).

    State Changes:
    - Creates the provider. Its API key is encrypted and shown only as its last 4 characters.

    Security:
    - Requires a valid session token.
    """
    return llm_providers.create_provider(db, interfaces.write_audit, mask, settings, operator, body)


@router.get("/{llm_provider_id}")
def read_provider(llm_provider_id: UUID, db: Db, _: CurrentOperator) -> LlmProviderOut:
    """Returns one LLM provider.

    Business Rules:
    - Returns 404 LLM_PROVIDER_NOT_FOUND if no provider has this id.

    Security:
    - Requires a valid session token.
    - The API key is never shown in full, only its last 4 characters.
    """
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
    """Updates a provider. Only the fields you send change.

    Business Rules:
    - The built-in RECONIX provider accepts only a new API key, even
      while active. Any other active provider cannot be changed.

    State Changes:
    - Updates the provider.

    Security:
    - Requires a valid session token.
    """
    return llm_providers.update_provider(
        db, interfaces.write_audit, mask, settings, operator, llm_provider_id, body
    )


@router.delete("/{llm_provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(
    llm_provider_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> None:
    """Deletes a provider, or archives it when agent runs used it.

    Business Rules:
    - The built-in RECONIX provider can be deleted and added back. The active provider can be
      deleted: that leaves no active model until the person chooses the next one.
    - A provider that agent runs used is archived: it leaves the lists and its API key is
      removed, but its row stays so the runs keep their history.

    State Changes:
    - Deletes the provider, or archives it (its key is removed). Removing the active one
      leaves no provider with `is_active`.

    Security:
    - Requires a valid session token.
    """
    llm_providers.delete_provider(db, interfaces.write_audit, operator, llm_provider_id)


@router.post("/{llm_provider_id}/activate")
def activate_provider(
    llm_provider_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> LlmProviderActivation:
    """Sets an LLM provider as the active one.

    Business Rules:
    - A provider on this computer becomes active immediately.
    - Any other provider returns a `configuration` approval and becomes active once a person
      approves it.

    State Changes:
    - Sets the provider active, or creates a configuration approval request.

    Security:
    - Requires a valid session token.
    """
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
    """Tests connectivity to the configured LLM provider.

    Execution Behavior:
    - Sends one fixed prompt that contains no Reconix data and reports whether the provider
      answered and its response latency.

    State Changes:
    - None. The test changes nothing.

    Security:
    - Requires a valid session token.
    """
    return await llm_providers.test_provider(
        db, interfaces.write_audit, settings, operator, llm_provider_id
    )


@router.get("/{llm_provider_id}/models")
async def list_models(
    llm_provider_id: UUID,
    db: Db,
    _: CurrentOperator,
    settings: CurrentSettings,
) -> LlmProviderModelsOut:
    """Lists the models a provider has.

    Business Rules:
    - An OLLAMA provider lists its Ollama's models; an OPENAI_API_COMPATIBLE provider on
      this computer (LM Studio, for example) lists what its server returns at /models.
    - An OPENAI, ANTHROPIC or DEEPSEEK provider lists the models its service offers for
      the saved key; without a saved key it returns 422 PROVIDER_KEY_MISSING.
    - RECONIX and OpenAI-compatible servers off this computer return 422
      MODEL_LIST_NOT_SUPPORTED.

    Security:
    - Requires a valid session token.
    - The saved API key is sent only to the provider's own address: the server on this
      computer, or the cloud service's fixed address (never a typed one).
    """
    return await llm_providers.list_models(db, settings, llm_provider_id)
