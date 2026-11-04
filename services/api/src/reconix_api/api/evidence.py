"""Masked evidence, and showing one masked value once (disclosure)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.disclosure import DisclosureVault, make_vault
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.approvals import ApprovalOut
from reconix_api.schemas.disclosures import DisclosedValueOut, DisclosureRequest, HiddenValueOut
from reconix_api.schemas.findings import EvidenceOut
from reconix_api.services import disclosures, findings
from reconix_api.services.decisions import approval_out

router = APIRouter(prefix="/evidence", tags=["evidence"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


def get_vault(settings: CurrentSettings) -> DisclosureVault:
    return make_vault(settings)


CurrentVault = Annotated[DisclosureVault, Depends(get_vault)]


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


@router.get("/{evidence_id}/hidden-values")
def list_hidden_values(
    evidence_id: UUID, db: Db, _: CurrentOperator, vault: CurrentVault
) -> list[HiddenValueOut]:
    """Lists the masked values in this evidence that a person may ask to see, by index and kind.
    The values themselves are never listed."""
    return disclosures.list_hidden_values(db, vault, evidence_id)


@router.post("/{evidence_id}/disclosures", status_code=202)
def request_disclosure(
    evidence_id: UUID,
    body: DisclosureRequest,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    vault: CurrentVault,
    settings: CurrentSettings,
) -> ApprovalOut:
    """Asks to see one masked value. This returns a `disclosure` approval; once a person approves
    it, reveal the value once with the reveal endpoint. Returns 404 HIDDEN_VALUE_NOT_FOUND if the
    evidence has no value with this index."""
    approval = disclosures.request_disclosure(
        db, interfaces.write_audit, operator, vault, evidence_id, body.index
    )
    return approval_out(approval, settings.approval_ttl_minutes)


@router.post("/{evidence_id}/disclosures/{approval_id}/reveal")
def reveal_value(
    evidence_id: UUID,
    approval_id: UUID,
    response: Response,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    vault: CurrentVault,
    settings: CurrentSettings,
) -> DisclosedValueOut:
    """Shows the real value once, after its `disclosure` approval was approved. The approval is
    used up, so a second call returns 409 APPROVAL_ALREADY_USED. Returns 409 APPROVAL_NOT_GRANTED
    if it is not approved yet, or 409 APPROVAL_EXPIRED after its time limit."""
    response.headers["Cache-Control"] = "no-store"
    return disclosures.reveal_value(
        db, interfaces.write_audit, operator, vault, settings, evidence_id, approval_id
    )
