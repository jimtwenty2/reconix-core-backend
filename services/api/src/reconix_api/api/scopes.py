"""Scope drafts: create, edit, read, submit."""

from uuid import UUID

from fastapi import APIRouter, status

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, RequireOperator
from reconix_api.schemas.scopes import ScopeDraft, ScopeOut, ScopeSubmit, ScopeSubmitted
from reconix_api.services import scopes

router = APIRouter(prefix="/scopes", tags=["scopes"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_scope(
    body: ScopeDraft, db: Db, operator: RequireOperator, interfaces: CurrentInterfaces
) -> ScopeOut:
    return scopes.create_draft(db, interfaces.write_audit, operator, body)


@router.get("/{manifest_id}")
def read_scope(manifest_id: UUID, db: Db, _: CurrentOperator) -> ScopeOut:
    return scopes.read_scope(db, manifest_id)


@router.put("/{manifest_id}")
def update_scope(
    manifest_id: UUID,
    body: ScopeDraft,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
) -> ScopeOut:
    return scopes.update_draft(db, interfaces.write_audit, operator, manifest_id, body)


@router.post("/{manifest_id}/submit", status_code=status.HTTP_201_CREATED)
def submit_scope(
    manifest_id: UUID,
    body: ScopeSubmit,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
) -> ScopeSubmitted:
    """Creates the DRAFT assessment and a scope approval."""
    return scopes.submit(db, interfaces.write_audit, operator, manifest_id, body)
