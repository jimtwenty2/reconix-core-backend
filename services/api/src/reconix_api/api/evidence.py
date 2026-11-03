"""Masked evidence."""

from uuid import UUID

from fastapi import APIRouter

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentOperator
from reconix_api.schemas.findings import EvidenceOut
from reconix_api.services import findings

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("/{evidence_id}")
def read_evidence(evidence_id: UUID, db: Db, _: CurrentOperator) -> EvidenceOut:
    """Returns one piece of evidence that supports a finding. Any secret in it was masked before it
    was saved. Returns 404 EVIDENCE_NOT_FOUND if there is no evidence with this id."""
    return findings.read_evidence(db, evidence_id)
