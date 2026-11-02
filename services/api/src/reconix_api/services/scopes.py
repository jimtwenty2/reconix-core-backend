"""Scope flow: draft -> edit -> submit (DRAFT assessment + scope approval) -> approve or reject."""

import ipaddress
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.orm import Session as Db
from sqlalchemy.orm import sessionmaker

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    ApprovedScope,
    ChatScope,
    GetApprovedScope,
    Operator,
    WriteAudit,
)
from reconix_api.models import Approval, Assessment, ScopeManifest, ScopeTarget
from reconix_api.models.enums import ApprovalStatus, AssessmentStatus, ManifestStatus
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import scopes as scope_repo
from reconix_api.schemas.scopes import (
    AssessmentOut,
    ScopeDraft,
    ScopeOut,
    ScopeSubmit,
    ScopeSubmitted,
    ScopeTargetOut,
    ScopeUpdate,
)
from reconix_api.services.approvals import snapshot_hash
from reconix_api.services.audit import audit

ENGAGEMENT_PREFIX = "RCX"


# ---------------------------------------------------------------------------
# Draft and edit
# ---------------------------------------------------------------------------


def create_draft(
    db: Db, write_audit: WriteAudit, operator: Operator, session_id: UUID, draft: ScopeDraft
) -> ScopeOut:
    """A new draft in your own session."""
    if session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SESSION", "You can only draft a scope in your own session.")
    manifest = ScopeManifest(
        session_id=operator.session_id, version=scope_repo.next_version(db, operator.session_id)
    )
    _apply_draft(manifest, draft)
    scope_repo.add(db, manifest)
    scope_repo.replace_targets(db, manifest.manifest_id, _targets(manifest.manifest_id, draft))
    db.commit()
    audit(
        write_audit, "SCOPE_DRAFTED", operator, details={"manifest_id": str(manifest.manifest_id)}
    )
    return read_scope(db, manifest.manifest_id)


def update_draft(
    db: Db, write_audit: WriteAudit, operator: Operator, manifest_id: UUID, draft: ScopeDraft
) -> ScopeOut:
    manifest = _get_manifest(db, manifest_id, lock=True)
    _ensure_editable(manifest)
    _apply_draft(manifest, draft)
    scope_repo.replace_targets(db, manifest_id, _targets(manifest_id, draft))
    db.commit()
    audit(write_audit, "SCOPE_EDITED", operator, details={"manifest_id": str(manifest_id)})
    return read_scope(db, manifest_id)


def patch_draft(
    db: Db, write_audit: WriteAudit, operator: Operator, manifest_id: UUID, changes: ScopeUpdate
) -> ScopeOut:
    """Only the fields sent change; the result is checked like a new draft."""
    current = read_scope(db, manifest_id)
    merged = {
        **current.model_dump(include=set(ScopeDraft.model_fields) - {"targets"}),
        "targets": [t.model_dump(exclude={"scope_target_id"}) for t in current.targets],
        **changes.model_dump(exclude_unset=True),
    }
    try:
        draft = ScopeDraft.model_validate(merged)
    except ValidationError as error:
        fields = [
            {"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in error.errors()
        ]
        raise ApiError(
            422, "VALIDATION_ERROR", "The scope is not valid.", {"fields": fields}
        ) from error
    return update_draft(db, write_audit, operator, manifest_id, draft)


def list_session_scopes(db: Db, session_id: UUID) -> list[ScopeOut]:
    return [read_scope(db, row.manifest_id) for row in scope_repo.list_by_session(db, session_id)]


def read_scope(db: Db, manifest_id: UUID) -> ScopeOut:
    manifest = _get_manifest(db, manifest_id)
    targets = scope_repo.list_targets(db, manifest_id)
    return ScopeOut(
        manifest_id=manifest.manifest_id,
        version=manifest.version,
        manifests_status=manifest.manifests_status,
        max_risk=manifest.max_risk,
        allowed_tools=manifest.allowed_tools,
        allowed_ports=manifest.allowed_ports or [],
        allowed_actions=manifest.allowed_actions,
        allowed_methods=manifest.allowed_methods,
        starts_at=manifest.starts_at,
        ends_at=manifest.ends_at,
        limitations=manifest.limitations,
        decided_by=manifest.decided_by,
        decided_at=manifest.decided_at,
        reject_reason=manifest.reject_reason,
        session_id=manifest.session_id,
        assessment_id=manifest.assessment_id,
        targets=[
            ScopeTargetOut(
                scope_target_id=t.scope_target_id, type=t.type, value=t.value, excluded=t.excluded
            )
            for t in targets
        ],
    )


def read_assessment(db: Db, assessment_id: UUID) -> AssessmentOut:
    assessment = assessment_repo.get(db, assessment_id)
    if assessment is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    return _assessment_out(assessment)


# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------


def submit(
    db: Db, write_audit: WriteAudit, operator: Operator, manifest_id: UUID, body: ScopeSubmit
) -> ScopeSubmitted:
    """Creates (or reuses) the session's DRAFT assessment and a scope approval."""
    manifest = _get_manifest(db, manifest_id, lock=True)
    _ensure_editable(manifest)
    targets = scope_repo.list_targets(db, manifest_id)
    if not any(not t.excluded for t in targets):
        raise ApiError(422, "SCOPE_HAS_NO_TARGETS", "Add at least one target that is not excluded.")

    assessment = _draft_assessment(db, operator, manifest.session_id, body)
    manifest.assessment_id = assessment.assessment_id
    snapshot = scope_snapshot(manifest, targets)
    approval = approval_repo.add(
        db,
        Approval(
            kind="scope",
            subject_snapshot=snapshot,
            subject_hash=snapshot_hash(snapshot),
            manifest_id=manifest_id,
        ),
    )
    db.commit()
    audit(
        write_audit,
        "SCOPE_SUBMITTED",
        operator,
        assessment.assessment_id,
        {"manifest_id": str(manifest_id), "approval_id": str(approval.approval_id)},
    )
    return ScopeSubmitted(
        scope=read_scope(db, manifest_id),
        assessment=_assessment_out(assessment),
        approval_id=approval.approval_id,
    )


def scope_snapshot(manifest: ScopeManifest, targets: list[ScopeTarget]) -> dict[str, Any]:
    """What a person approves. Any change to it changes the hash. allowed_ports is in it
    only when set, so a scope submitted before ports existed keeps its hash."""
    snapshot = {
        "manifest_id": str(manifest.manifest_id),
        "version": manifest.version,
        "max_risk": manifest.max_risk,
        "allowed_tools": sorted(manifest.allowed_tools),
        "allowed_actions": sorted(manifest.allowed_actions),
        "allowed_methods": sorted(manifest.allowed_methods),
        "starts_at": _utc_text(manifest.starts_at),
        "ends_at": _utc_text(manifest.ends_at),
        "limitations": manifest.limitations,
        "targets": sorted(
            ({"type": t.type, "value": t.value, "excluded": t.excluded} for t in targets),
            key=lambda t: (t["excluded"], t["type"], t["value"]),
        ),
    }
    if manifest.allowed_ports:
        snapshot["allowed_ports"] = sorted(manifest.allowed_ports)
    return snapshot


def next_engagement_code(latest: str | None, year: int) -> str:
    """RCX-2026-0001, RCX-2026-0002, ... numbering starts again each year."""
    number = int(latest.rsplit("-", 1)[1]) + 1 if latest else 1
    return f"{ENGAGEMENT_PREFIX}-{year}-{number:04d}"


# ---------------------------------------------------------------------------
# Approve and reject (called from services/decisions.py)
# ---------------------------------------------------------------------------


def approve_scope(db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval) -> None:
    manifest = _get_manifest(db, approval.manifest_id, lock=True)
    targets = scope_repo.list_targets(db, manifest.manifest_id)
    if snapshot_hash(scope_snapshot(manifest, targets)) != approval.subject_hash:
        raise ApiError(409, "SCOPE_CHANGED", "The scope changed after it was submitted.")
    assessment = assessment_repo.get(db, manifest.assessment_id)

    now = datetime.now(UTC)
    approval.approval_status = ApprovalStatus.APPROVED
    approval.decided_by = operator.actor
    approval.decided_at = now
    approval.consumed_at = now  # a scope approval is used the moment it is given
    manifest.manifests_status = ManifestStatus.APPROVED
    manifest.decided_by = operator.actor
    manifest.decided_at = now
    assessment.assessment_status = AssessmentStatus.ACTIVE
    db.commit()
    audit(
        write_audit,
        "SCOPE_APPROVED",
        operator,
        assessment.assessment_id,
        {"manifest_id": str(manifest.manifest_id), "approval_id": str(approval.approval_id)},
    )


def reject_scope(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval, reason: str | None
) -> None:
    """The assessment stays DRAFT; the next scope version can be submitted for it."""
    manifest = _get_manifest(db, approval.manifest_id, lock=True)
    assessment_id = manifest.assessment_id

    now = datetime.now(UTC)
    approval.approval_status = ApprovalStatus.REJECTED
    approval.decided_by = operator.actor
    approval.decided_at = now
    approval.reason = reason
    manifest.manifests_status = ManifestStatus.REJECTED
    manifest.decided_by = operator.actor
    manifest.decided_at = now
    manifest.reject_reason = reason
    manifest.assessment_id = None  # one manifest per assessment: free it for the next version
    db.commit()
    audit(
        write_audit,
        "SCOPE_REJECTED",
        operator,
        assessment_id,
        {"manifest_id": str(manifest.manifest_id), "approval_id": str(approval.approval_id)},
    )


# ---------------------------------------------------------------------------
# get_approved_scope: one of the 6 shared functions
# ---------------------------------------------------------------------------


def make_get_approved_scope(session_factory: sessionmaker[Db]) -> GetApprovedScope:
    def get_approved_scope(assessment_id: UUID) -> ApprovedScope:
        with session_factory() as db:
            manifest = scope_repo.get_approved(db, assessment_id)
            if manifest is None:
                raise LookupError("SCOPE_NOT_APPROVED")
            return to_approved_scope(manifest, scope_repo.list_targets(db, manifest.manifest_id))

    return get_approved_scope


def to_approved_scope(manifest: ScopeManifest, targets: list[ScopeTarget]) -> ApprovedScope:
    return ApprovedScope(
        assessment_id=manifest.assessment_id,
        allowed_tools=manifest.allowed_tools,
        allowed_ports=manifest.allowed_ports or [],
        max_risk=manifest.max_risk,
        window_start=manifest.starts_at,
        window_end=manifest.ends_at,
        **target_lists(targets),
    )


def to_chat_scope(manifest: ScopeManifest, targets: list[ScopeTarget]) -> ChatScope:
    """The scope as the chat sees it. Anything not APPROVED is a draft to the agent."""
    approved = manifest.manifests_status == ManifestStatus.APPROVED
    return ChatScope(
        assessment_id=manifest.assessment_id,
        status="APPROVED" if approved else "DRAFT",
        allowed_tools=manifest.allowed_tools,
        allowed_ports=manifest.allowed_ports or [],
        max_risk=manifest.max_risk,
        window_start=manifest.starts_at,
        window_end=manifest.ends_at,
        **target_lists(targets),
    )


def target_lists(targets: list[ScopeTarget]) -> dict[str, list[str]]:
    lists: dict[str, list[str]] = {
        "excluded_targets": [],
        "ip_ranges": [],
        "domains": [],
        "url_prefixes": [],
        "repo_paths": [],
    }
    for target in targets:
        if target.excluded:
            lists["excluded_targets"].append(target.value)
        elif target.type in ("ip", "cidr"):
            lists["ip_ranges"].append(str(ipaddress.ip_network(target.value, strict=False)))
        elif target.type == "domain":
            lists["domains"].append(target.value)
        elif target.type == "url":
            lists["url_prefixes"].append(target.value)
        elif target.type == "path":
            lists["repo_paths"].append(target.value)
    return lists


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_manifest(db: Db, manifest_id: UUID, lock: bool = False) -> ScopeManifest:
    manifest = (
        scope_repo.get_for_update(db, manifest_id) if lock else scope_repo.get(db, manifest_id)
    )
    if manifest is None:
        raise ApiError(404, "SCOPE_NOT_FOUND", "No scope with this id.")
    return manifest


def _ensure_editable(manifest: ScopeManifest) -> None:
    """Only a draft that has not been submitted can change."""
    if manifest.manifests_status != ManifestStatus.DRAFT or manifest.assessment_id is not None:
        raise ApiError(
            409,
            "SCOPE_NOT_EDITABLE",
            "This scope was already submitted or decided. Create a new draft instead.",
            {"manifests_status": manifest.manifests_status},
        )


def _apply_draft(manifest: ScopeManifest, draft: ScopeDraft) -> None:
    manifest.max_risk = draft.max_risk
    manifest.allowed_tools = [tool.value for tool in draft.allowed_tools]
    manifest.allowed_ports = sorted(set(draft.allowed_ports))
    manifest.allowed_actions = draft.allowed_actions
    manifest.allowed_methods = draft.allowed_methods
    manifest.starts_at = draft.starts_at
    manifest.ends_at = draft.ends_at
    manifest.limitations = draft.limitations


def _targets(manifest_id: UUID, draft: ScopeDraft) -> list[ScopeTarget]:
    return [
        ScopeTarget(manifest_id=manifest_id, type=t.type, value=t.value, excluded=t.excluded)
        for t in draft.targets
    ]


def _draft_assessment(
    db: Db, operator: Operator, session_id: UUID, body: ScopeSubmit
) -> Assessment:
    """One assessment per session. A resubmit after a rejection reuses it."""
    assessment = assessment_repo.get_by_session(db, session_id)
    if assessment is not None:
        if assessment.assessment_status != AssessmentStatus.DRAFT:
            raise ApiError(
                409,
                "ASSESSMENT_ALREADY_ACTIVE",
                "This session's assessment already has an approved scope.",
                {"assessment_id": str(assessment.assessment_id)},
            )
        assessment.name = body.name
        assessment.type = body.type
        return assessment

    year = datetime.now(UTC).year
    prefix = f"{ENGAGEMENT_PREFIX}-{year}-"
    code = next_engagement_code(assessment_repo.latest_engagement_code(db, prefix), year)
    return assessment_repo.add(
        db,
        Assessment(
            engagement_code=code,
            name=body.name,
            type=body.type,
            created_by=operator.actor,
            session_id=session_id,
        ),
    )


def _utc_text(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def _assessment_out(assessment: Assessment) -> AssessmentOut:
    return AssessmentOut.model_validate(assessment, from_attributes=True)
