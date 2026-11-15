"""AI providers: the model settings the agent uses. Only one is active at a time.

An API key is encrypted with Fernet before it is saved, and only its last 4 characters
are ever shown. A provider on this computer becomes active at once. One that runs
anywhere else would send prompts and findings off this computer, so a person approves
it first with a `configuration` approval, for exactly the settings they saw.

The built-in RECONIX provider comes from the migration. Its address and model are always
RECONIX_MODEL_* in .env; only its key can be changed (a typed key replaces
RECONIX_MODEL_API_KEY), and it can be removed and added back. The active provider of any
other type cannot be changed, so an approved address or key cannot be swapped afterwards;
it can be removed, which leaves no model active.

Locks are always taken in the same order as approving: the approval first, then the
provider.
"""

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.orm import Session as Db

from reconix_api.core import provider_checks, provider_keys, provider_urls
from reconix_api.core.agent import provider_config
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import Approval, LlmProvider
from reconix_api.models.enums import ApprovalStatus, ProviderType
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import llm_providers as provider_repo
from reconix_api.schemas.llm_providers import (
    LlmProviderIn,
    LlmProviderModelsOut,
    LlmProviderOut,
    LlmProviderTestOut,
    LlmProviderUpdate,
)
from reconix_api.services.approvals import expires_at, snapshot_hash
from reconix_api.services.audit import audit

ACTIVATE = "ACTIVATE_LLM_PROVIDER"  # config_change["change"] of an activation approval
ACTIVE_REMOVED = "no model is active until the person chooses one"  # audit reason
# The 3 cloud services always need a key, and never count as local: an address on this
# computer can still be a proxy or a tunnel to the cloud.
CLOUD_TYPES = {ProviderType.OPENAI, ProviderType.ANTHROPIC, ProviderType.DEEPSEEK}
# With no address, these call RECONIX_OLLAMA_URL.
OLLAMA_TYPES = {ProviderType.OLLAMA}
DISPLAY_NAME_LENGTH = 100  # llm_providers.display_name is VARCHAR(100)


def list_providers(db: Db) -> list[LlmProviderOut]:
    return [provider_out(provider) for provider in provider_repo.list_visible(db)]


def read_provider(db: Db, llm_provider_id: UUID) -> LlmProviderOut:
    return provider_out(_get(db, llm_provider_id))


def create_provider(
    db: Db,
    write_audit: WriteAudit,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    body: LlmProviderIn,
) -> LlmProviderOut:
    """Saved inactive, with the key encrypted. Activate it to use it."""
    if body.provider_type == ProviderType.RECONIX:
        _check_reconix_add(db, body)
    api_key = body.api_key.get_secret_value() if body.api_key else None
    base_url = body.base_url or None
    source = _key_source(db, body, base_url)
    _refuse_secrets(mask, {"model_name": body.model_name, "base_url": base_url})
    has_key = api_key is not None or (source is not None and source.api_key_encrypted is not None)
    check_settings(body.provider_type, base_url, has_key=has_key)
    provider = LlmProvider(
        provider_type=body.provider_type,
        display_name=_masked_name(mask, body.display_name),
        base_url=base_url,
        model_name=body.model_name,
        created_by=operator.actor,
    )
    _set_key(settings, provider, api_key)
    if source is not None:
        provider.api_key_encrypted = source.api_key_encrypted
        provider.api_key_last4 = source.api_key_last4
    provider_repo.add(db, provider)
    db.commit()
    _audit(write_audit, "LLM_PROVIDER_ADDED", operator, provider)
    return provider_out(provider)


def update_provider(
    db: Db,
    write_audit: WriteAudit,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    llm_provider_id: UUID,
    changes: LlmProviderUpdate,
) -> LlmProviderOut:
    """Only the fields sent change. The type cannot change: add a new provider instead."""
    provider = _get(db, llm_provider_id, lock=True)
    if provider.provider_type == ProviderType.RECONIX:
        return _update_reconix_key(db, write_audit, settings, operator, provider, changes)
    _ensure_editable(provider)
    merged = _validated(
        {
            "provider_type": provider.provider_type,
            "display_name": provider.display_name,
            "model_name": provider.model_name,
            "base_url": provider.base_url,
            **changes.model_dump(exclude_unset=True, exclude={"api_key"}),
        }
    )
    new_key = "api_key" in changes.model_fields_set
    api_key = changes.api_key.get_secret_value() if changes.api_key else None
    base_url = merged.base_url or None
    # A key was typed for one address: a new address never gets the old key.
    moved = base_url != provider.base_url and not new_key and provider.api_key_encrypted
    if moved:
        new_key = True
    has_key = api_key is not None if new_key else provider.api_key_encrypted is not None
    _refuse_secrets(mask, {"model_name": merged.model_name, "base_url": base_url})
    check_settings(provider.provider_type, base_url, has_key=has_key)
    provider.display_name = _masked_name(mask, merged.display_name)
    provider.model_name = merged.model_name
    provider.base_url = base_url
    if new_key:
        _set_key(settings, provider, api_key)
    db.commit()
    _audit(write_audit, "LLM_PROVIDER_EDITED", operator, provider)
    return provider_out(provider)


def delete_provider(
    db: Db, write_audit: WriteAudit, operator: Operator, llm_provider_id: UUID
) -> None:
    """A provider no agent run used is deleted. One that runs used is archived instead: it
    leaves the lists and its key is removed, but its row stays, so their history keeps its
    model. Its open activation approval, if any, is closed as EXPIRED.

    The active provider can be removed: nothing is made active in its place, so the person's
    next step chooses one. Until then a run says NO_ACTIVE_PROVIDER — no model is used that
    the person did not pick."""
    open_approval = provider_repo.activation_approval(db, llm_provider_id, ACTIVATE, lock=True)
    provider = _get(db, llm_provider_id, lock=True)
    expired = _expire(open_approval)
    # The one audit line must say the model that was answering has stopped answering.
    reason = ACTIVE_REMOVED if provider.is_active else None
    if provider_repo.run_count(db, llm_provider_id):
        provider.archived = True
        provider.is_active = False  # an archived row must not stay the active one
        provider.api_key_encrypted = None
        provider.api_key_last4 = None
        db.commit()
        _audit_expired(write_audit, operator, provider, expired)
        _audit(write_audit, "LLM_PROVIDER_ARCHIVED", operator, provider, reason=reason)
        return
    provider_repo.delete(db, provider)
    db.commit()
    _audit_expired(write_audit, operator, provider, expired)
    _audit(write_audit, "LLM_PROVIDER_REMOVED", operator, provider, reason=reason)


def activate(
    db: Db, write_audit: WriteAudit, operator: Operator, llm_provider_id: UUID, ttl_minutes: int
) -> tuple[LlmProviderOut, Approval | None]:
    """A provider on this computer, and the built-in RECONIX provider, are active at once.
    Any other one gets a `configuration` approval and stays inactive until a person
    approves it. RECONIX's address is set in .env by whoever installs Reconix and can never
    be changed through the API, so there is no edited address for an approval to guard.

    One open approval per provider: one that lapsed, or that is for settings the
    provider no longer has, is closed as EXPIRED first."""
    open_approval = provider_repo.activation_approval(db, llm_provider_id, ACTIVATE, lock=True)
    provider = _get(db, llm_provider_id, lock=True)
    if provider.is_active:
        raise ApiError(409, "PROVIDER_ALREADY_ACTIVE", "This provider is already active.")
    local = provider.provider_type == ProviderType.RECONIX or is_local(
        provider.provider_type, provider.base_url
    )
    if not local:
        _refuse_if_waiting(provider, open_approval, ttl_minutes)
    expired = _expire(open_approval)
    approval = None
    if local:
        _make_active(db, provider)
    else:
        approval = approval_repo.add(db, _activation_approval(provider))
    db.commit()
    _audit_expired(write_audit, operator, provider, expired)
    if local:
        _audit(write_audit, "LLM_PROVIDER_ACTIVATED", operator, provider)
    else:
        _audit(write_audit, "APPROVAL_REQUESTED", operator, provider, approval)
    return provider_out(provider), approval


# ---------------------------------------------------------------------------
# The `configuration` approval that activates a provider off this computer
# ---------------------------------------------------------------------------


def is_activation(approval: Approval) -> bool:
    return (
        approval.kind == "configuration"
        and (approval.config_change or {}).get("change") == ACTIVATE
    )


def approve_activation(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval
) -> None:
    """Called from services/decisions.py, which has locked the approval. Only for the
    exact settings the person saw: if the provider changed since, it is refused.
    Approving uses it."""
    provider = _get(db, UUID(approval.config_change["llm_provider_id"]), lock=True)
    if activation_hash(provider) != approval.subject_hash:
        # Not what the person was shown: this approval is spent, and a new one is needed.
        approval.approval_status = ApprovalStatus.EXPIRED
        approval.reason = "PROVIDER_CHANGED"
        db.commit()
        _audit(write_audit, "APPROVAL_EXPIRED", operator, provider, approval, "PROVIDER_CHANGED")
        raise ApiError(
            409,
            "PROVIDER_CHANGED",
            "The provider changed after the approval was asked. Activate it again.",
        )
    now = datetime.now(UTC)
    approval.approval_status = ApprovalStatus.APPROVED
    approval.decided_by = operator.actor
    approval.decided_at = now
    approval.consumed_at = now  # single use: switching the provider is its one use
    _make_active(db, provider)
    db.commit()
    _audit(write_audit, "APPROVAL_GRANTED", operator, provider, approval)


def reject_activation(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval, reason: str | None
) -> None:
    approval.approval_status = ApprovalStatus.REJECTED
    approval.decided_by = operator.actor
    approval.decided_at = datetime.now(UTC)
    approval.reason = reason
    db.commit()
    audit(
        write_audit,
        "APPROVAL_REJECTED",
        operator,
        details={
            "llm_provider_id": approval.config_change["llm_provider_id"],
            "approval_id": str(approval.approval_id),
        },
    )


def activation_snapshot(provider: LlmProvider) -> dict[str, Any]:
    """What the person approves: where prompts and findings will go, and which key."""
    return {
        "change": ACTIVATE,
        "llm_provider_id": str(provider.llm_provider_id),
        "provider_type": provider.provider_type,
        "display_name": provider.display_name,
        "base_url": provider.base_url,
        "model_name": provider.model_name,
        "api_key_last4": provider.api_key_last4,
    }


def activation_hash(provider: LlmProvider) -> str:
    """SHA-256 over the snapshot and the encrypted key, so a new key needs a new
    approval even when its last 4 characters are the same."""
    encrypted_key = hashlib.sha256(provider.api_key_encrypted or b"").hexdigest()
    return snapshot_hash({**activation_snapshot(provider), "api_key_encrypted": encrypted_key})


def _activation_approval(provider: LlmProvider) -> Approval:
    return Approval(
        kind="configuration",
        subject_snapshot=activation_snapshot(provider),
        subject_hash=activation_hash(provider),
        config_change={"change": ACTIVATE, "llm_provider_id": str(provider.llm_provider_id)},
    )


def _refuse_if_waiting(
    provider: LlmProvider, open_approval: Approval | None, ttl_minutes: int
) -> None:
    """409 while an approval for these exact settings still waits."""
    if open_approval is None or open_approval.approval_status != ApprovalStatus.PENDING:
        return
    lapsed = datetime.now(UTC) >= expires_at(open_approval.requested_at, ttl_minutes)
    if not lapsed and open_approval.subject_hash == activation_hash(provider):
        raise ApiError(
            409,
            "APPROVAL_PENDING",
            "This provider already waits for an approval.",
            {"approval_id": str(open_approval.approval_id)},
        )


def _expire(approval: Approval | None) -> Approval | None:
    """Closes a still-PENDING approval as EXPIRED and returns it, for its audit line."""
    if approval is None or approval.approval_status != ApprovalStatus.PENDING:
        return None
    approval.approval_status = ApprovalStatus.EXPIRED
    return approval


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def check_settings(provider_type: ProviderType, base_url: str | None, has_key: bool) -> None:
    """The same rules the model call applies, so a provider that saves can be called."""
    if provider_type == ProviderType.OPENAI_API_COMPATIBLE and not base_url:
        raise ApiError(
            422, "PROVIDER_URL_MISSING", "An OpenAI-compatible provider needs its address."
        )
    if provider_type in CLOUD_TYPES and not has_key:
        raise ApiError(
            422, "PROVIDER_KEY_MISSING", f"The {provider_type} provider needs an API key."
        )
    if base_url:
        provider_urls.check(base_url)


def is_local(provider_type: ProviderType, base_url: str | None) -> bool:
    """On this computer: the address that is really called is localhost or a loopback
    IP. The 3 cloud services never are. RECONIX calls RECONIX_MODEL_URL (the Reconix
    team's server); Ollama with no address calls RECONIX_OLLAMA_URL."""
    if provider_type in CLOUD_TYPES:
        return False
    if provider_type == ProviderType.RECONIX:
        base_url = provider_urls.reconix_model_url()
    elif not base_url and provider_type in OLLAMA_TYPES:
        base_url = provider_urls.default_ollama_url()
    return bool(base_url) and provider_urls.is_local_address(base_url)


def provider_out(provider: LlmProvider) -> LlmProviderOut:
    return LlmProviderOut(
        llm_provider_id=provider.llm_provider_id,
        provider_type=provider.provider_type,
        display_name=provider.display_name,
        base_url=provider.base_url,
        api_key_last4=provider.api_key_last4,
        model_name=provider.model_name,
        is_active=provider.is_active,
        is_local=is_local(provider.provider_type, provider.base_url),
        created_by=provider.created_by,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


def _refuse_secrets(mask: MaskSecrets, fields: dict[str, str | None]) -> None:
    """The model name and the address are saved and shown as typed, so one that looks
    like a secret is refused. The message never repeats the value."""
    for field, value in fields.items():
        if value and mask(value)[1]:
            raise ApiError(
                422,
                "SECRET_NOT_ALLOWED",
                f"The {field} looks like a secret. Put the key in api_key.",
                {"field": field},
            )


def _make_active(db: Db, provider: LlmProvider) -> None:
    provider_repo.deactivate_all(db)
    provider.is_active = True
    db.flush()


def _key_source(db: Db, body: LlmProviderIn, base_url: str | None) -> LlmProvider | None:
    """The saved provider whose key a new one copies (copy_key_from), or None. Only the same
    type at the same address: a key never goes anywhere it was not typed for."""
    if body.copy_key_from is None:
        return None
    if body.api_key is not None:
        raise ApiError(422, "KEY_GIVEN_TWICE", "Send an api_key or copy_key_from, not both.")
    source = _get(db, body.copy_key_from)
    if source.provider_type != body.provider_type or (source.base_url or None) != base_url:
        raise ApiError(
            422,
            "KEY_NOT_COPYABLE",
            "A key is copied only from a provider of the same type at the same address.",
        )
    return source


def _set_key(settings: Settings, provider: LlmProvider, api_key: str | None) -> None:
    provider.api_key_encrypted = provider_keys.encrypt(settings, api_key) if api_key else None
    provider.api_key_last4 = provider_keys.last4(api_key) if api_key else None


def _masked_name(mask: MaskSecrets, display_name: str) -> str:
    # A mask label can be longer than the secret it hides.
    return mask(display_name)[0][:DISPLAY_NAME_LENGTH]


def _validated(values: dict[str, Any]) -> LlmProviderIn:
    try:
        return LlmProviderIn.model_validate(values)
    except ValidationError as error:
        fields = [
            {"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in error.errors()
        ]
        raise ApiError(
            422, "VALIDATION_ERROR", "The provider is not valid.", {"fields": fields}
        ) from None


def _check_reconix_add(db: Db, body: LlmProviderIn) -> None:
    """RECONIX can be added back after it was removed, once. Its address is always
    RECONIX_MODEL_URL, so none is taken here."""
    if any(p.provider_type == ProviderType.RECONIX for p in provider_repo.list_visible(db)):
        raise ApiError(
            422, "PROVIDER_TYPE_NOT_ALLOWED", "The built-in RECONIX provider is already there."
        )
    if body.base_url or body.copy_key_from is not None:
        raise ApiError(
            422,
            "BUILT_IN_PROVIDER",
            "The RECONIX address is set by RECONIX_MODEL_URL in .env; only a key can be given.",
        )


def _update_reconix_key(
    db: Db,
    write_audit: WriteAudit,
    settings: Settings,
    operator: Operator,
    provider: LlmProvider,
    changes: LlmProviderUpdate,
) -> LlmProviderOut:
    """Only RECONIX's key changes, even while it is active: its address is fixed by .env
    and never needed an approval. A blank key goes back to RECONIX_MODEL_API_KEY."""
    other = changes.model_fields_set - {"api_key"}
    if other:
        raise ApiError(
            409,
            "BUILT_IN_PROVIDER",
            "Only the key of the built-in RECONIX provider can be changed.",
            {"fields": sorted(other)},
        )
    if "api_key" in changes.model_fields_set:
        _set_key(
            settings, provider, changes.api_key.get_secret_value() if changes.api_key else None
        )
    db.commit()
    _audit(write_audit, "LLM_PROVIDER_EDITED", operator, provider)
    return provider_out(provider)


def _ensure_editable(provider: LlmProvider) -> None:
    if provider.is_active:
        raise ApiError(
            409,
            "PROVIDER_IS_ACTIVE",
            "Make another provider active before you change this one.",
        )


async def test_provider(
    db: Db, write_audit: WriteAudit, settings: Settings, operator: Operator, llm_provider_id: UUID
) -> LlmProviderTestOut:
    """Send the provider's model one fixed prompt with no Reconix data. A custom address
    off this computer must not resolve to a private network, so the test can never be
    used to probe it. One audit line per test."""
    provider = _get(db, llm_provider_id)
    if provider.base_url and not is_local(provider.provider_type, provider.base_url):
        provider_checks.ensure_public_host(provider.base_url)
    config = provider_config(settings, provider, provider.model_name)
    model_name, provider_type = provider.model_name, provider.provider_type
    db.rollback()  # no transaction stays open while the model answers
    result = await provider_checks.try_provider(config)
    details = {
        "llm_provider_id": str(llm_provider_id),
        "provider_type": provider_type,
        "ok": result.ok,
        "code": result.code,
    }
    audit(write_audit, "LLM_PROVIDER_TESTED", operator, details=details)
    return LlmProviderTestOut(model_name=model_name, **result.__dict__)


async def list_models(db: Db, settings: Settings, llm_provider_id: UUID) -> LlmProviderModelsOut:
    """The models a provider has: an Ollama's or an OpenAI-compatible server's on this
    computer (LM Studio...), or a cloud service's for its saved key. RECONIX and custom
    servers off this computer are not asked."""
    provider = _get(db, llm_provider_id)
    local = is_local(provider.provider_type, provider.base_url)
    if provider.provider_type in OLLAMA_TYPES and local:
        base_url = provider.base_url
        db.rollback()
        return LlmProviderModelsOut(models=await provider_checks.local_models(base_url))
    if provider.provider_type == ProviderType.OPENAI_API_COMPATIBLE and local:
        base_url = provider.base_url or ""
        key = provider_config(settings, provider, provider.model_name).api_key
        db.rollback()
        return LlmProviderModelsOut(models=await provider_checks.compatible_models(base_url, key))
    if provider.provider_type.value in provider_checks.CLOUD_MODEL_LISTS:
        provider_type = provider.provider_type.value
        key = provider_config(settings, provider, provider.model_name).api_key
        db.rollback()
        return LlmProviderModelsOut(models=await provider_checks.cloud_models(provider_type, key))
    raise ApiError(
        422,
        "MODEL_LIST_NOT_SUPPORTED",
        "Only Ollama, a cloud service or an OpenAI-compatible server on this computer "
        "can list its models.",
    )


def _get(db: Db, llm_provider_id: UUID, lock: bool = False) -> LlmProvider:
    provider = provider_repo.get(db, llm_provider_id, lock=lock)
    # An archived provider is gone for every change; agent runs read it through the repository.
    if provider is None or provider.archived:
        raise ApiError(404, "LLM_PROVIDER_NOT_FOUND", "No AI provider with this id.")
    return provider


def _audit_expired(
    write_audit: WriteAudit, operator: Operator, provider: LlmProvider, expired: Approval | None
) -> None:
    if expired is not None:
        _audit(write_audit, "APPROVAL_EXPIRED", operator, provider, expired)


def _audit(
    write_audit: WriteAudit,
    event_type: str,
    operator: Operator,
    provider: LlmProvider,
    approval: Approval | None = None,
    reason: str | None = None,
) -> None:
    """Never the key or the address: which provider, which model, which approval, and why.
    The model name is kept because a removed row would otherwise leave no record of what
    was answering."""
    details = {
        "llm_provider_id": str(provider.llm_provider_id),
        "provider_type": str(provider.provider_type),
        "model_name": provider.model_name,
    }
    if approval is not None:
        details["approval_id"] = str(approval.approval_id)
    if reason is not None:
        details["reason"] = reason
    audit(write_audit, event_type, operator, details=details)
