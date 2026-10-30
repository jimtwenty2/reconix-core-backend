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
    LlmProviderOut,
    LlmProviderUpdate,
)
from reconix_api.services import decisions, llm_providers

router = APIRouter(prefix="/llm-providers", tags=["llm providers"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.get("")
def list_providers(db: Db, _: CurrentOperator) -> list[LlmProviderOut]:
    """Oldest first; the built-in RECONIX provider is always there."""
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
    """Saved inactive. The API key is encrypted and never shown again, only its last 4
    characters. OPENAI, ANTHROPIC and DEEPSEEK need a key; OPENAI_API_COMPATIBLE needs
    base_url."""
    return llm_providers.create_provider(db, interfaces.write_audit, mask, settings, operator, body)


@router.get("/{llm_provider_id}")
def read_provider(llm_provider_id: UUID, db: Db, _: CurrentOperator) -> LlmProviderOut:
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
    """Only the fields sent change. The built-in and the active provider cannot change."""
    return llm_providers.update_provider(
        db, interfaces.write_audit, mask, settings, operator, llm_provider_id, body
    )


@router.delete("/{llm_provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(
    llm_provider_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> None:
    """Not the built-in or the active provider, nor one that agent runs used."""
    llm_providers.delete_provider(db, interfaces.write_audit, operator, llm_provider_id)


@router.post("/{llm_provider_id}/activate")
def activate_provider(
    llm_provider_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> LlmProviderActivation:
    """A provider on this computer is active at once. Any other one answers with a
    `configuration` approval and becomes active when it is approved."""
    ttl_minutes = settings.approval_ttl_minutes
    provider, approval = llm_providers.activate(
        db, interfaces.write_audit, operator, llm_provider_id, ttl_minutes
    )
    approval_out = decisions.approval_out(approval, ttl_minutes) if approval else None
    return LlmProviderActivation(llm_provider=provider, approval=approval_out)
