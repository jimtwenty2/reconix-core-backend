"""Limit settings: changing a loop limit needs a `configuration` approval.

The rules (names, bounds, "refuse if the limits moved since") live in the harness,
reconix_ai/harness/limits.py. The limits in use are the `after` of the newest approved
and used limit change, so no extra table is needed. Until a change is approved, the old
limits stay in use.
"""

from datetime import UTC, datetime

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import LoopLimitSettings, Operator, WriteAudit
from reconix_api.core.limits import (
    DEFAULT_LIMITS_JSON,
    LIMIT_RULES,
    LimitError,
    apply_limit_change,
    limits_from_json,
    limits_to_json,
    plan_limit_change,
)
from reconix_api.models import Approval
from reconix_api.models.enums import ApprovalStatus
from reconix_api.repositories import approvals as approval_repo
from reconix_api.schemas.limit_settings import LimitBounds, LimitChangeIn, LimitSettingsOut
from reconix_api.services.approvals import snapshot_hash, still_open_after
from reconix_api.services.audit import audit

SETTING = "loop_limits"  # config_change["setting"] of a limit change

MESSAGES = {
    "UNKNOWN_LIMIT": "There is no limit with this name.",
    "NOT_A_NUMBER": "A limit must be a whole number.",
    "OUT_OF_RANGE": "This limit is outside the allowed range.",
    "NO_CHANGE": "These are the limits in use already.",
    "BAD_CHANGE": "This limit change cannot be read.",
    "LIMITS_CHANGED": "The limits changed after this approval was asked. Ask again.",
}


def current_limits(db: Db) -> LoopLimitSettings:
    """The limits the loop check uses now."""
    latest = approval_repo.latest_limit_change(db)
    after = latest.config_change["after"] if latest is not None else DEFAULT_LIMITS_JSON
    try:
        return LoopLimitSettings(**limits_to_json(limits_from_json(after)))
    except LimitError:
        # Fails closed: no action can pass the check until the saved limits are fixed.
        raise ApiError(
            500, "LIMIT_SETTINGS_UNREADABLE", "The saved loop limits cannot be read."
        ) from None


def read_limit_settings(db: Db, ttl_minutes: int) -> LimitSettingsOut:
    waiting = approval_repo.pending_limit_changes(db, still_open_after(ttl_minutes))
    return LimitSettingsOut(
        limits=current_limits(db),
        defaults=LoopLimitSettings(**DEFAULT_LIMITS_JSON),
        bounds={
            name: LimitBounds(lowest=rule.lowest, highest=rule.highest)
            for name, rule in LIMIT_RULES.items()
        },
        pending_approval_ids=[approval.approval_id for approval in waiting],
    )


def request_limit_change(
    db: Db, write_audit: WriteAudit, operator: Operator, body: LimitChangeIn
) -> Approval:
    """A PENDING `configuration` approval; nothing changes until a person approves it."""
    current = limits_from_json(current_limits(db).model_dump())
    try:
        change = plan_limit_change(current, body.changes).as_json()
    except LimitError as error:
        raise _limit_error(error) from None
    approval = approval_repo.add(
        db,
        Approval(
            kind="configuration",
            subject_snapshot=change,
            subject_hash=snapshot_hash(change),
            config_change=change,
        ),
    )
    db.commit()
    audit(write_audit, "APPROVAL_REQUESTED", operator, details=_details(approval))
    return approval


def is_limit_change(approval: Approval) -> bool:
    return (
        approval.kind == "configuration"
        and (approval.config_change or {}).get("setting") == SETTING
    )


def approve_limit_change(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval
) -> None:
    """Called from services/decisions.py, which has locked the approval. Approving applies
    the change and uses the approval up. If the limits moved since it was asked for, it
    is spent and nothing changes."""
    approval_repo.lock_limit_changes(db)
    current = limits_from_json(current_limits(db).model_dump())
    try:
        if snapshot_hash(approval.config_change) != approval.subject_hash:
            raise LimitError("BAD_CHANGE")
        apply_limit_change(current, approval.config_change)
    except LimitError as error:
        approval.approval_status = ApprovalStatus.EXPIRED
        approval.reason = error.code
        db.commit()
        audit(write_audit, "APPROVAL_EXPIRED", operator, details=_details(approval, error.code))
        raise _limit_error(error) from None
    now = datetime.now(UTC)
    approval.approval_status = ApprovalStatus.APPROVED
    approval.decided_by = operator.actor
    approval.decided_at = now
    approval.consumed_at = now  # single use: the new limits are in use from now on
    db.commit()
    audit(write_audit, "APPROVAL_GRANTED", operator, details=_details(approval))


def reject_limit_change(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval, reason: str | None
) -> None:
    approval.approval_status = ApprovalStatus.REJECTED
    approval.decided_by = operator.actor
    approval.decided_at = datetime.now(UTC)
    approval.reason = reason
    db.commit()
    audit(write_audit, "APPROVAL_REJECTED", operator, details=_details(approval))


def _details(approval: Approval, reason: str | None = None) -> dict[str, object]:
    """Which approval and which limits changed; limits are plain numbers, never secrets."""
    details: dict[str, object] = {
        "approval_id": str(approval.approval_id),
        "kind": approval.kind,
        "setting": SETTING,
        "changed": approval.config_change.get("changed", {}),
    }
    if reason is not None:
        details["reason"] = reason
    return details


def _limit_error(error: LimitError) -> ApiError:
    status = 409 if error.code == "LIMITS_CHANGED" else 422
    details = {"limit": error.name} if error.name else {}
    return ApiError(status, error.code, MESSAGES.get(error.code, error.code), details)
