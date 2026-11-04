"""Request and response shapes for /assessments/{id}/actions and /actions."""

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from reconix_ai.harness.catalog import is_known_tool
from reconix_api.models.enums import ActionStatus, RiskLevel, ToolRunStatus


class ActionIn(BaseModel):
    """One tool run. Arguments are a list, never one shell string."""

    model_config = ConfigDict(str_strip_whitespace=True)  # "   " fails min_length

    tool: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=2048)
    arguments: list[Annotated[str, Field(min_length=1, max_length=2048)]] = Field(
        default_factory=list, max_length=50
    )
    purpose: Literal["discovery", "scan", "validation"] = "scan"

    @field_validator("tool")
    @classmethod
    def tool_is_in_catalog(cls, value: str) -> str:
        if not is_known_tool(value):
            raise ValueError("tool is not in the Kali catalog (tool_specs.json)")
        return value.strip().upper()  # one form everywhere: "masscan" -> "MASSCAN"


class ToolRunOut(BaseModel):
    tool_run_id: UUID
    attempt_no: int
    tool_run_status: ToolRunStatus
    exit_code: int | None
    error: str | None
    masked_count: int
    request_count: int
    output_masked: str | None
    started_at: datetime | None
    finished_at: datetime | None
    approval_id: UUID | None


class ActionOut(BaseModel):
    action_id: UUID
    tool: str
    args: list[str]
    target: str
    purpose: str
    risk_level: RiskLevel | None
    action_status: ActionStatus
    guardrail_report: dict[str, Any]
    source: str
    created_at: datetime
    assessment_id: UUID
    manifest_id: UUID
    approval_id: UUID | None = None  # set when a person must approve it
    tool_runs: list[ToolRunOut] = Field(default_factory=list)
