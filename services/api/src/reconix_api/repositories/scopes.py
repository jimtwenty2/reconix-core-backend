"""Database access for scope_manifests and scope_targets."""

from collections import defaultdict
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import ScopeManifest, ScopeTarget
from reconix_api.models.enums import ManifestStatus


def add(db: Db, manifest: ScopeManifest) -> ScopeManifest:
    db.add(manifest)
    db.flush()
    return manifest


def get(db: Db, manifest_id: UUID) -> ScopeManifest | None:
    return db.get(ScopeManifest, manifest_id)


def get_for_update(db: Db, manifest_id: UUID) -> ScopeManifest | None:
    """Locks the row until commit, so two requests cannot change it at once."""
    return db.scalar(
        select(ScopeManifest).where(ScopeManifest.manifest_id == manifest_id).with_for_update()
    )


def next_version(db: Db, session_id: UUID) -> int:
    latest = db.scalar(
        select(func.max(ScopeManifest.version)).where(ScopeManifest.session_id == session_id)
    )
    return (latest or 0) + 1


def get_approved(db: Db, assessment_id: UUID) -> ScopeManifest | None:
    return db.scalar(
        select(ScopeManifest).where(
            ScopeManifest.assessment_id == assessment_id,
            ScopeManifest.manifests_status == ManifestStatus.APPROVED,
        )
    )


def list_targets(db: Db, manifest_id: UUID) -> list[ScopeTarget]:
    query = (
        select(ScopeTarget)
        .where(ScopeTarget.manifest_id == manifest_id)
        .order_by(ScopeTarget.excluded, ScopeTarget.type, ScopeTarget.value)
    )
    return list(db.scalars(query))


def replace_targets(db: Db, manifest_id: UUID, targets: list[ScopeTarget]) -> None:
    db.execute(delete(ScopeTarget).where(ScopeTarget.manifest_id == manifest_id))
    db.add_all(targets)
    db.flush()


def list_by_session(db: Db, session_id: UUID) -> list[ScopeManifest]:
    query = (
        select(ScopeManifest)
        .where(ScopeManifest.session_id == session_id)
        .order_by(ScopeManifest.version)
    )
    return list(db.scalars(query))


def approved_targets(db: Db, assessment_ids: list[UUID]) -> dict[UUID, list[str]]:
    """The approved scope's targets per assessment, excluded ones left out."""
    query = (
        select(ScopeManifest.assessment_id, ScopeTarget.value)
        .join(ScopeTarget, ScopeTarget.manifest_id == ScopeManifest.manifest_id)
        .where(
            ScopeManifest.assessment_id.in_(assessment_ids),
            ScopeManifest.manifests_status == ManifestStatus.APPROVED,
            ScopeTarget.excluded.is_(False),
        )
        .order_by(ScopeTarget.value)
    )
    targets: dict[UUID, list[str]] = defaultdict(list)
    for assessment_id, value in db.execute(query):
        targets[assessment_id].append(value)
    return targets
