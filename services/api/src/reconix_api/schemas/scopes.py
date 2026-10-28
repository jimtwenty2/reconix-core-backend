"""Request and response shapes for scope manifests and assessments."""

import ipaddress
import re
from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from reconix_api.core.interfaces import ToolName
from reconix_api.models.enums import AssessmentStatus, ManifestStatus, RiskLevel

DOMAIN = re.compile(r"^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+$", re.IGNORECASE)


class ScopeTargetIn(BaseModel):
    type: Literal["domain", "ip", "cidr", "url"]
    value: str = Field(min_length=1, max_length=2048)
    excluded: bool = False

    @model_validator(mode="after")
    def value_matches_type(self) -> Self:
        if self.type == "ip":
            ipaddress.ip_address(self.value)
        elif self.type == "cidr":
            ipaddress.ip_network(self.value, strict=False)
        elif self.type == "url" and not self.value.startswith(("http://", "https://")):
            raise ValueError("a url target must start with http:// or https://")
        elif self.type == "domain" and not DOMAIN.match(self.value):
            raise ValueError("not a valid domain")
        return self


class ScopeTargetOut(ScopeTargetIn):
    scope_target_id: UUID


class ScopeDraft(BaseModel):
    """A new draft, or a draft after a partial edit is applied."""

    max_risk: RiskLevel = RiskLevel.LOW
    allowed_tools: list[ToolName] = Field(min_length=1)
    allowed_actions: list[Literal["discovery", "scan", "validation"]] = Field(default_factory=list)
    allowed_methods: list[Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]] = (
        Field(default_factory=list)
    )
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    limitations: str | None = Field(default=None, max_length=4000)
    targets: list[ScopeTargetIn] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def window_is_in_order(self) -> Self:
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        return self


class ScopeUpdate(BaseModel):
    """A partial edit of a draft: only the fields sent change. Sending targets replaces them all."""

    max_risk: RiskLevel | None = None
    allowed_tools: list[ToolName] | None = None
    allowed_actions: list[Literal["discovery", "scan", "validation"]] | None = None
    allowed_methods: (
        list[Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]] | None
    ) = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    limitations: str | None = Field(default=None, max_length=4000)
    targets: list[ScopeTargetIn] | None = Field(default=None, max_length=200)


class ScopeSubmit(BaseModel):
    """Submitting creates the DRAFT assessment, so it carries the assessment's name and type."""

    name: str = Field(min_length=1, max_length=200)
    type: str = Field(min_length=1, max_length=60)  # e.g. web_url, network


class ScopeOut(BaseModel):
    manifest_id: UUID
    version: int
    manifests_status: ManifestStatus
    max_risk: RiskLevel
    allowed_tools: list[str]
    allowed_actions: list[str]
    allowed_methods: list[str]
    starts_at: datetime | None
    ends_at: datetime | None
    limitations: str | None
    decided_by: str | None
    decided_at: datetime | None
    reject_reason: str | None
    session_id: UUID
    assessment_id: UUID | None
    targets: list[ScopeTargetOut]


class AssessmentOut(BaseModel):
    assessment_id: UUID
    engagement_code: str
    name: str
    type: str
    assessment_status: AssessmentStatus
    created_by: str
    created_at: datetime
    updated_at: datetime
    session_id: UUID


class AssessmentUpdate(BaseModel):
    """Rename, or finish an ACTIVE assessment. Cancelling is DELETE."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    type: str | None = Field(default=None, min_length=1, max_length=60)
    assessment_status: Literal[AssessmentStatus.COMPLETED] | None = None


class ScopeSubmitted(BaseModel):
    scope: ScopeOut
    assessment: AssessmentOut
    approval_id: UUID
