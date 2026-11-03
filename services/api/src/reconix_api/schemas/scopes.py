"""Request and response shapes for scope manifests and assessments."""

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from reconix_ai.harness.catalog import is_known_tool
from reconix_api.core.code_files import check_code_path
from reconix_api.models.enums import AssessmentStatus, ManifestStatus, RiskLevel


def _check_tools(tools: list[str] | None) -> list[str] | None:
    """Every tool must be in the Kali catalog (tool_specs.json)."""
    for tool in tools or []:
        if not is_known_tool(tool):
            raise ValueError(f"tool {tool!r} is not in the Kali catalog (tool_specs.json)")
    return tools


DOMAIN = re.compile(r"^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+$", re.IGNORECASE)
Port = Annotated[int, Field(ge=1, le=65535)]
MAX_PORTS = 1000


class ScopeTargetIn(BaseModel):
    type: Literal["domain", "ip", "cidr", "url", "path"]  # path: uploaded source code
    value: str = Field(min_length=1, max_length=2048)
    excluded: bool = False

    @model_validator(mode="after")
    def value_matches_type(self) -> Self:
        if self.type == "ip":
            ipaddress.ip_address(self.value)
        elif self.type == "cidr":
            ipaddress.ip_network(self.value, strict=False)
        elif self.type == "url":
            check_url(self.value)
        elif self.type == "domain" and not DOMAIN.match(self.value):
            raise ValueError("not a valid domain")
        elif self.type == "path":
            check_code_path(self.value)
        return self


def check_url(value: str) -> None:
    """The scope goes to the model and the safety checks as written: no spaces or control
    characters (text hidden on a new line), and no user:password in it."""
    if not value.startswith(("http://", "https://")):
        raise ValueError("a url target must start with http:// or https://")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("a url target cannot hold spaces or control characters")
    if "@" in urlsplit(value).netloc:
        raise ValueError("a url target cannot hold a user name or password")


class ScopeTargetOut(ScopeTargetIn):
    scope_target_id: UUID


class ScopeDraft(BaseModel):
    """A new draft, or a draft after a partial edit is applied."""

    max_risk: RiskLevel = RiskLevel.LOW
    allowed_tools: list[str] = Field(min_length=1)
    # The ports nmap may scan. Empty puts no limit on ports.
    allowed_ports: list[Port] = Field(default_factory=list, max_length=MAX_PORTS)
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

    @model_validator(mode="after")
    def tools_in_catalog(self) -> Self:
        _check_tools(self.allowed_tools)
        return self


class ScopeUpdate(BaseModel):
    """A partial edit of a draft: only the fields sent change. Sending targets replaces them all."""

    max_risk: RiskLevel | None = None
    allowed_tools: list[str] | None = None
    allowed_ports: list[Port] | None = Field(default=None, max_length=MAX_PORTS)
    allowed_actions: list[Literal["discovery", "scan", "validation"]] | None = None
    allowed_methods: (
        list[Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]] | None
    ) = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    limitations: str | None = Field(default=None, max_length=4000)
    targets: list[ScopeTargetIn] | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def tools_in_catalog(self) -> Self:
        _check_tools(self.allowed_tools)
        return self


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
    allowed_ports: list[int]
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
