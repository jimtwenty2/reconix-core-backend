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
    """Returns one piece of evidence that supports a finding.

    Business Rules:
    - Returns 404 EVIDENCE_NOT_FOUND if no evidence has this id.

    Security:
    - Requires a valid session token.
    - Any secret in the evidence is masked before it is saved.
    """
    return findings.read_evidence(db, evidence_id)
