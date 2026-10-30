"""Database access for llm_providers and their `configuration` approvals."""

from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as Db

from reconix_api.models import AgentRun, Approval, LlmProvider
from reconix_api.models.enums import ApprovalStatus


def add(db: Db, provider: LlmProvider) -> LlmProvider:
    db.add(provider)
    db.flush()
    return provider


def get(db: Db, llm_provider_id: UUID, lock: bool = False) -> LlmProvider | None:
    return db.get(LlmProvider, llm_provider_id, with_for_update=lock)


def list_all(db: Db) -> list[LlmProvider]:
    return list(db.scalars(select(LlmProvider).order_by(LlmProvider.created_at)))


def delete(db: Db, provider: LlmProvider) -> None:
    db.delete(provider)


def deactivate_all(db: Db) -> None:
    db.execute(update(LlmProvider).where(LlmProvider.is_active).values(is_active=False))


def run_count(db: Db, llm_provider_id: UUID) -> int:
    query = select(func.count()).where(AgentRun.llm_provider_id == llm_provider_id)
    return db.scalar(query) or 0


def activation_approval(
    db: Db, llm_provider_id: UUID, change: str, lock: bool = False
) -> Approval | None:
    """The newest configuration approval that activates this provider. lock holds it
    until commit, so it cannot be decided at the same time."""
    query = (
        select(Approval)
        .where(
            Approval.kind == "configuration",
            Approval.config_change["change"].astext == change,
            Approval.config_change["llm_provider_id"].astext == str(llm_provider_id),
        )
        .order_by(Approval.requested_at.desc())
        .limit(1)
    )
    if lock:
        query = query.with_for_update()
    return db.scalar(query)


def approved_activation(db: Db, llm_provider_id: UUID, change: str) -> Approval | None:
    """The newest APPROVED configuration approval that activated this provider."""
    query = (
        select(Approval)
        .where(
            Approval.kind == "configuration",
            Approval.approval_status == ApprovalStatus.APPROVED,
            Approval.config_change["change"].astext == change,
            Approval.config_change["llm_provider_id"].astext == str(llm_provider_id),
        )
        .order_by(Approval.decided_at.desc())
        .limit(1)
    )
    return db.scalar(query)
