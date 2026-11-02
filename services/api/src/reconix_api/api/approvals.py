"""Waiting approvals, and approving or rejecting one."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.models.enums import ApprovalStatus
from reconix_api.schemas.approvals import ApprovalDecision, ApprovalKind, ApprovalOut
from reconix_api.services import decisions

router = APIRouter(prefix="/approvals", tags=["approvals"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.get("")
def list_approvals(
    db: Db,
    _: CurrentOperator,
    settings: CurrentSettings,
    status: ApprovalStatus = ApprovalStatus.PENDING,
    kind: ApprovalKind | None = None,
) -> list[ApprovalOut]:
    """Lists the approvals that are waiting for a person. Filter by status and kind to see others,
    such as the ones already decided."""
    return decisions.list_approvals(db, settings.approval_ttl_minutes, status, kind)


@router.get("/{approval_id}")
def read_approval(
    approval_id: UUID, db: Db, _: CurrentOperator, settings: CurrentSettings
) -> ApprovalOut:
    """Returns one approval, whether it is still waiting or already decided, together with the time
    it expires. Returns 404 APPROVAL_NOT_FOUND if there is no approval with this id."""
    return decisions.read_approval(db, approval_id, settings.approval_ttl_minutes)


@router.post("/{approval_id}/approve")
async def approve(
    approval_id: UUID,
    body: ApprovalDecision,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> ApprovalOut:
    """Approves a waiting approval. Approving an action also runs it, so read the action afterwards
    to see its tool run."""
    return await decisions.approve(db, interfaces, mask, settings, operator, approval_id, body)


@router.post("/{approval_id}/reject")
async def reject(
    approval_id: UUID,
    body: ApprovalDecision,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> ApprovalOut:
    """Rejects a waiting approval. Send a reason so the audit log shows why. A rejected action
    never runs. Returns 409 APPROVAL_ALREADY_DECIDED if someone already decided it, or 409
    APPROVAL_EXPIRED if it is older than its time limit."""
    return await decisions.reject(
        db, interfaces, operator, settings.approval_ttl_minutes, approval_id, body
    )
