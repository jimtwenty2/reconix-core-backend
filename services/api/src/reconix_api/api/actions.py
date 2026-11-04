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
    """Sends one tool step through the safety checks.

    Business Rules:
    - A LOW-risk step runs immediately.
    - A MEDIUM- or HIGH-risk step waits for a person; the response carries an approval_id.
    - A step that fails any safety check is BLOCKED and returns 422 ACTION_BLOCKED.

    Execution Behavior:
    - Runs the harness checks, and runs the tool now only when the step is LOW risk.

    State Changes:
    - Creates an action, and an approval request when the step needs one.

    Security:
    - Requires a valid session token.
    """
    return await actions.send_action(db, interfaces, mask, settings, operator, assessment_id, body)


@router.get("/assessments/{assessment_id}/actions")
def list_actions(assessment_id: UUID, db: Db, _: CurrentOperator) -> list[ActionOut]:
    """Lists every action in the assessment, newest first, with its tool runs.

    Business Rules:
    - Returns 404 ASSESSMENT_NOT_FOUND if the assessment does not exist.

    Security:
    - Requires a valid session token.
    """
    return actions.list_actions(db, assessment_id)


@router.get("/actions/{action_id}")
def read_action(action_id: UUID, db: Db, _: CurrentOperator) -> ActionOut:
    """Returns one action with its risk level, status, the approval it is waiting for (if any), and
    its tool runs.

    Business Rules:
    - Returns 404 ACTION_NOT_FOUND if no action has this id.

    Security:
    - Requires a valid session token.
    """
    return actions.read_action(db, action_id)
