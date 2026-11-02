"""Scope manifests: draft in a session, list, read, edit, submit."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.scopes import (
    ScopeDraft,
    ScopeOut,
    ScopeSubmit,
    ScopeSubmitted,
    ScopeUpdate,
)
from reconix_api.services import scopes

router = APIRouter(tags=["scope manifests"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.post("/sessions/{session_id}/scope-manifests", status_code=status.HTTP_201_CREATED)
def create_scope(
    session_id: UUID,
    body: ScopeDraft,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
) -> ScopeOut:
    """Starts a new scope draft in your own session, as the session's next scope version. Edit it
    with PATCH, then submit it for approval. Returns 403 NOT_YOUR_SESSION if the session is not
    yours."""
    return scopes.create_draft(db, interfaces.write_audit, operator, session_id, body)


@router.get("/sessions/{session_id}/scope-manifests")
def list_scopes(session_id: UUID, db: Db, _: CurrentOperator) -> list[ScopeOut]:
    """Lists every scope version in the session, oldest first."""
    return scopes.list_session_scopes(db, session_id)


@router.get("/scope-manifests/{manifest_id}")
def read_scope(manifest_id: UUID, db: Db, _: CurrentOperator) -> ScopeOut:
    """Returns one scope version: its targets, exclusions, time window, allowed tools and maximum
    risk. Returns 404 SCOPE_NOT_FOUND if there is no scope with this id."""
    return scopes.read_scope(db, manifest_id)


@router.patch("/scope-manifests/{manifest_id}")
def update_scope(
    manifest_id: UUID,
    body: ScopeUpdate,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
) -> ScopeOut:
    """Changes a scope draft. Only the fields you send change, and only a draft that has not been
    submitted can be changed."""
    return scopes.patch_draft(db, interfaces.write_audit, operator, manifest_id, body)


@router.post("/scope-manifests/{manifest_id}/submit", status_code=status.HTTP_201_CREATED)
def submit_scope(
    manifest_id: UUID,
    body: ScopeSubmit,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> ScopeSubmitted:
    """Submits the scope for approval. This creates the assessment, in DRAFT, and a scope approval
    for a person to decide."""
    return scopes.submit(
        db, interfaces.write_audit, operator, manifest_id, body, settings.approval_ttl_minutes
    )
