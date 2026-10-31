"""Request and response shapes for /llm-providers. An API key goes in, never out."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr

from reconix_api.models.enums import ProviderType
from reconix_api.schemas.approvals import ApprovalOut

# A model id such as "gpt-4o", "llama3.1:8b" or "hf.co/user/model:Q4": no spaces.
MODEL_NAME = r"^[\w.:/@+-]+$"


class LlmProviderIn(BaseModel):
    provider_type: ProviderType
    display_name: str = Field(min_length=1, max_length=100)
    model_name: str = Field(min_length=1, max_length=100, pattern=MODEL_NAME)
    # Empty: the cloud service's own address, or RECONIX_OLLAMA_URL for Ollama.
    base_url: str | None = Field(default=None, max_length=2048)
    api_key: SecretStr | None = Field(default=None, min_length=16, max_length=500)


class LlmProviderUpdate(BaseModel):
    """Only the fields sent change. A new api_key replaces the old one; null removes it."""

    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    model_name: str | None = Field(default=None, min_length=1, max_length=100, pattern=MODEL_NAME)
    base_url: str | None = Field(default=None, max_length=2048)
    api_key: SecretStr | None = Field(default=None, min_length=16, max_length=500)


class LlmProviderOut(BaseModel):
    llm_provider_id: UUID
    provider_type: ProviderType
    display_name: str
    base_url: str | None
    api_key_last4: str | None  # the key itself is never shown
    model_name: str
    is_active: bool
    # true: it runs on this computer and is made active at once. false: activating it
    # needs a `configuration` approval first.
    is_local: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class LlmProviderActivation(BaseModel):
    """approval is set when the provider runs off this computer: it becomes active once
    the approval is approved with /approvals/{id}/approve."""

    llm_provider: LlmProviderOut
    approval: ApprovalOut | None = None


class LlmProviderTestOut(BaseModel):
    """One fixed test prompt, with no Reconix data in it."""

    ok: bool
    model_name: str
    latency_ms: int
    code: str | None = None  # why it failed, e.g. MODEL_UNAVAILABLE
    message: str | None = None


class LlmProviderModelsOut(BaseModel):
    models: list[str]  # e.g. ["reconix:latest", "bge-m3:latest"]
