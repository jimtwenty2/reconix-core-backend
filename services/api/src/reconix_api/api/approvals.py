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
    """Lists the approval requests waiting for a person.

    Business Rules:
    - Filter by status and kind to see others, such as those already decided.

    Security:
    - Requires a valid session token.
    """
    return decisions.list_approvals(db, settings.approval_ttl_minutes, status, kind)


@router.get("/{approval_id}")
def read_approval(
    approval_id: UUID, db: Db, _: CurrentOperator, settings: CurrentSettings
) -> ApprovalOut:
    """Returns one approval request, whether it is waiting or already decided, with its expiry time.

    Business Rules:
    - Returns 404 APPROVAL_NOT_FOUND if no approval has this id.

    Security:
    - Requires a valid session token.
    """
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
    """Approves a waiting approval request.

    Execution Behavior:
    - Approving an action also runs it; read the action afterward to see its tool run.

    State Changes:
    - Marks the approval approved, and runs the approved action when the approval is for one.

    Security:
    - Requires a valid session token.
    """
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
    """Rejects a waiting approval request.

    Business Rules:
    - Send a reason so the audit log records it.
    - A rejected action never runs.
    - Returns 409 APPROVAL_ALREADY_DECIDED if it was already decided, or 409 APPROVAL_EXPIRED if it
      is past its time limit.

    State Changes:
    - Marks the approval rejected.

    Security:
    - Requires a valid session token.
    """
    return await decisions.reject(
        db, interfaces, operator, settings.approval_ttl_minutes, approval_id, body
    )
