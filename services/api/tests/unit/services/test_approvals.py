from datetime import UTC, datetime, timedelta

import pytest

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import RiskLevel
from reconix_api.services.approvals import (
    ApprovalState,
    ApprovalStatus,
    ensure_can_decide,
    ensure_can_use,
    expires_at,
)

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


def make_approval(**overrides) -> ApprovalState:
    values = {
        "status": ApprovalStatus.PENDING,
        "risk": RiskLevel.MEDIUM,
        "target": "172.20.0.5",
        "created_at": NOW,
        "expires_at": expires_at(NOW, 30),
    }
    values.update(overrides)
    return ApprovalState(**values)


def code_of(call) -> str:
    with pytest.raises(ApiError) as error:
        call()
    return error.value.code


def test_expires_after_30_minutes():
    assert expires_at(NOW, 30) == NOW + timedelta(minutes=30)


def test_medium_can_be_approved_without_typing():
    ensure_can_decide(make_approval(), NOW, typed_target=None)


def test_high_needs_the_exact_target():
    approval = make_approval(risk=RiskLevel.HIGH)
    ensure_can_decide(approval, NOW, typed_target="172.20.0.5")
    assert code_of(lambda: ensure_can_decide(approval, NOW, "172.20.0.6")) == (
        "TARGET_CONFIRMATION_MISMATCH"
    )
    assert code_of(lambda: ensure_can_decide(approval, NOW, None)) == (
        "TARGET_CONFIRMATION_MISMATCH"
    )


def test_cannot_decide_after_expiry():
    late = NOW + timedelta(minutes=30)
    assert code_of(lambda: ensure_can_decide(make_approval(), late, None)) == "APPROVAL_EXPIRED"


def test_cannot_decide_twice():
    approval = make_approval(status=ApprovalStatus.APPROVED)
    assert code_of(lambda: ensure_can_decide(approval, NOW, None)) == "APPROVAL_ALREADY_DECIDED"


def test_approved_can_be_used_once():
    approval = make_approval(status=ApprovalStatus.APPROVED)
    ensure_can_use(approval, NOW)
    used = approval.model_copy(update={"used_at": NOW})
    assert code_of(lambda: ensure_can_use(used, NOW)) == "APPROVAL_ALREADY_USED"


@pytest.mark.parametrize(
    "status", [ApprovalStatus.PENDING, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED]
)
def test_only_approved_can_be_used(status):
    assert code_of(lambda: ensure_can_use(make_approval(status=status), NOW)) == (
        "APPROVAL_NOT_GRANTED"
    )


def test_cannot_use_after_expiry():
    approval = make_approval(status=ApprovalStatus.APPROVED)
    late = NOW + timedelta(minutes=31)
    assert code_of(lambda: ensure_can_use(approval, late)) == "APPROVAL_EXPIRED"
