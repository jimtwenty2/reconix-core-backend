"""Sending an action for an assessment, and reading actions with their tool runs."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.actions import ActionIn, ActionOut
from reconix_api.services import actions

router = APIRouter(tags=["actions"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.post("/assessments/{assessment_id}/actions", status_code=status.HTTP_201_CREATED)
async def send_action(
    assessment_id: UUID,
    body: ActionIn,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> ActionOut:
    """BLOCKED -> 422. LOW runs now. MEDIUM and HIGH return an approval_id to approve."""
    return await actions.send_action(db, interfaces, mask, settings, operator, assessment_id, body)


@router.get("/assessments/{assessment_id}/actions")
def list_actions(assessment_id: UUID, db: Db, _: CurrentOperator) -> list[ActionOut]:
    return actions.list_actions(db, assessment_id)


@router.get("/actions/{action_id}")
def read_action(action_id: UUID, db: Db, _: CurrentOperator) -> ActionOut:
    return actions.read_action(db, action_id)
