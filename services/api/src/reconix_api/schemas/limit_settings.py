"""Request and response shapes for /limit-settings."""

from uuid import UUID

from pydantic import BaseModel, Field, StrictInt

from reconix_api.core.interfaces import LoopLimitSettings


class LimitBounds(BaseModel):
    lowest: int
    highest: int


class LimitSettingsOut(BaseModel):
    limits: LoopLimitSettings  # in use now
    defaults: LoopLimitSettings  # the plan's limits
    bounds: dict[str, LimitBounds]  # what a change may ask for, per limit
    pending_approval_ids: list[UUID]  # changes still waiting for a person


class LimitChangeIn(BaseModel):
    """Only the limits to change, e.g. {"max_runs_per_assessment": 300}."""

    changes: dict[str, StrictInt] = Field(min_length=1, max_length=4)
