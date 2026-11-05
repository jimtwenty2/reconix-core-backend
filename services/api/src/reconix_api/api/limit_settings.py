"""The loop check's limits, and asking to change them."""

from typing import Annotated

from fastapi import APIRouter, Depends

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.approvals import ApprovalOut
from reconix_api.schemas.limit_settings import LimitChangeIn, LimitSettingsOut
from reconix_api.services import limit_settings
from reconix_api.services.decisions import approval_out

router = APIRouter(prefix="/limit-settings", tags=["limit settings"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.get("")
def read_limit_settings(db: Db, _: CurrentOperator, settings: CurrentSettings) -> LimitSettingsOut:
    """Returns the loop check's limits in use now, the default limits, the range each limit may
    take, and the ids of any changes still waiting for a person."""
    return limit_settings.read_limit_settings(db, settings.approval_ttl_minutes)


@router.post("", status_code=202)
def request_limit_change(
    body: LimitChangeIn,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> ApprovalOut:
    """Asks to change one or more loop limits. Nothing changes yet: this returns a `configuration`
    approval, and the new limits are used only after a person approves it. Returns 422 with
    UNKNOWN_LIMIT, NOT_A_NUMBER, OUT_OF_RANGE or NO_CHANGE if the change is not allowed."""
    approval = limit_settings.request_limit_change(db, interfaces.write_audit, operator, body)
    return approval_out(approval, settings.approval_ttl_minutes)
