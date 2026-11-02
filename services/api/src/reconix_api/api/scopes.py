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
    return scopes.create_draft(db, interfaces.write_audit, operator, session_id, body)


@router.get("/sessions/{session_id}/scope-manifests")
def list_scopes(session_id: UUID, db: Db, _: CurrentOperator) -> list[ScopeOut]:
    return scopes.list_session_scopes(db, session_id)


@router.get("/scope-manifests/{manifest_id}")
def read_scope(manifest_id: UUID, db: Db, _: CurrentOperator) -> ScopeOut:
    return scopes.read_scope(db, manifest_id)


@router.patch("/scope-manifests/{manifest_id}")
def update_scope(
    manifest_id: UUID,
    body: ScopeUpdate,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
) -> ScopeOut:
    """Only the fields sent change. Only a draft that was not submitted can change."""
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
    """Creates the DRAFT assessment and a scope approval."""
    return scopes.submit(
        db, interfaces.write_audit, operator, manifest_id, body, settings.approval_ttl_minutes
    )
