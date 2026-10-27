"""Action rules: the hash that pins what a person approved, and what happens after the check."""

import hashlib
import json
from enum import StrEnum

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Action, CheckResult, Decision, RiskLevel


class NextStep(StrEnum):
    RUN_NOW = "RUN_NOW"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


def action_hash(action: Action) -> str:
    """SHA-256 of the action in a fixed form. Any change to tool, target or arguments changes it."""
    canonical = json.dumps(action.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def next_step(result: CheckResult) -> NextStep:
    """BLOCKED -> 422. LOW runs now. MEDIUM and HIGH wait for a person."""
    if result.decision == Decision.BLOCKED:
        raise ApiError(
            422,
            "ACTION_BLOCKED",
            "The safety checks blocked this action.",
            {"blocked_by": result.blocked_by, "reason": result.reason, "risk": result.risk},
        )
    if result.risk == RiskLevel.LOW:
        return NextStep.RUN_NOW
    return NextStep.NEEDS_APPROVAL


def ensure_unchanged(approved_hash: str, action: Action) -> None:
    """Right before running: refuse if the action is not exactly what was approved."""
    if action_hash(action) != approved_hash:
        raise ApiError(409, "ACTION_CHANGED", "The action changed after it was approved.")
