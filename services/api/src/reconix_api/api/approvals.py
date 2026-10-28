"""Waiting approvals, and approving or rejecting one."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, RequireOperator
from reconix_api.schemas.approvals import ApprovalDecision, ApprovalOut
from reconix_api.services import decisions

router = APIRouter(prefix="/approvals", tags=["approvals"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.get("")
def list_pending_approvals(
    db: Db, _: CurrentOperator, settings: CurrentSettings
) -> list[ApprovalOut]:
    return decisions.list_pending(db, settings.approval_ttl_minutes)


@router.get("/{approval_id}")
def read_approval(
    approval_id: UUID, db: Db, _: CurrentOperator, settings: CurrentSettings
) -> ApprovalOut:
    return decisions.read_approval(db, approval_id, settings.approval_ttl_minutes)


@router.post("/{approval_id}/approve")
async def approve(
    approval_id: UUID,
    body: ApprovalDecision,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> ApprovalOut:
    """Approving an action also runs it; read the action afterwards for its tool run."""
    return await decisions.approve(db, interfaces, mask, settings, operator, approval_id, body)


@router.post("/{approval_id}/reject")
def reject(
    approval_id: UUID,
    body: ApprovalDecision,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> ApprovalOut:
    return decisions.reject(
        db, interfaces.write_audit, operator, settings.approval_ttl_minutes, approval_id, body
    )
