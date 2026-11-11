"""The derived finding confidence tier (schemas.findings.confidence_of + the computed field)."""

from reconix_api.models.enums import FindingStatus, SeverityStatus, ValidationStatus
from reconix_api.schemas.findings import Confidence, confidence_of

OPEN = FindingStatus.OPEN
UNCONF = ValidationStatus.UNCONFIRMED


def c(**kw):
    base = dict(
        validation_status=UNCONF,
        finding_status=OPEN,
        severity_status=SeverityStatus.MEDIUM,
        tools=["NUCLEI"],
    )
    base.update(kw)
    return confidence_of(**base)


def test_a_validated_finding_is_confirmed():
    assert c(validation_status=ValidationStatus.CONFIRMED) == Confidence.CONFIRMED


def test_a_person_false_positive_is_informational():
    assert c(finding_status=FindingStatus.FALSE_POSITIVE) == Confidence.INFORMATIONAL


def test_a_none_severity_fact_is_informational():
    assert c(severity_status=SeverityStatus.NONE) == Confidence.INFORMATIONAL


def test_a_verifier_tool_makes_it_firm():
    assert c(tools=["SQLMAP"]) == Confidence.FIRM
    assert c(tools=["DALFOX"]) == Confidence.FIRM
    assert c(tools=["NUCLEI_DAST"]) == Confidence.FIRM  # an OOB callback is strong evidence


def test_two_tools_agreeing_make_it_firm():
    assert c(tools=["NUCLEI", "NIKTO"]) == Confidence.FIRM


def test_a_single_scanner_match_is_tentative():
    assert c(tools=["NUCLEI"]) == Confidence.TENTATIVE


def test_confirmed_outranks_a_false_positive_mark():
    # a validation beats a person's stale FALSE_POSITIVE mark
    assert (
        c(validation_status=ValidationStatus.CONFIRMED, finding_status=FindingStatus.FALSE_POSITIVE)
        == Confidence.CONFIRMED
    )


def test_the_computed_field_is_on_findingout():
    from datetime import UTC, datetime
    from uuid import uuid4

    from reconix_api.schemas.findings import FindingOut

    out = FindingOut(
        finding_id=uuid4(),
        code="RCX-001",
        title="t",
        target="http://h",
        description="d",
        severity_status=SeverityStatus.HIGH,
        cvss_score=None,
        cwe_ids=[],
        owasp_id=[],
        cve_ids=[],
        impact=None,
        remediation=None,
        validation_status=UNCONF,
        finding_status=OPEN,
        reviewed_by=None,
        reviewed_at=None,
        created_at=datetime.now(UTC),
        assessment_id=uuid4(),
        tools=["SQLMAP"],
    )
    assert out.confidence == Confidence.FIRM
    assert out.model_dump()["confidence"] == "FIRM"
