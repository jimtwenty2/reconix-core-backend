"""Saving findings from a tool run (dedupe, sources, masked evidence) and reading them back."""

from collections.abc import Callable
from functools import partial
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import ToolName
from reconix_api.core.masking import MaskSecrets
from reconix_api.findings import json_mapping
from reconix_api.findings import nmap as nmap_findings
from reconix_api.findings.shape import NewFinding
from reconix_api.models import Evidence, Finding, ToolRun
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import findings as finding_repo
from reconix_api.schemas.findings import EvidenceOut, FindingOut

# One reader per Kali tool name: masked output -> (findings, requests sent).
# JSON tools share one reader through their mapping; the rest have their own.
READERS: dict[str, Callable[[str], tuple[list[NewFinding], int]]] = {
    "nmap": nmap_findings.read,
    **{name: partial(json_mapping.read, rule) for name, rule in json_mapping.MAPPINGS.items()},
}


def parse_run(tool: ToolName | str, output: str) -> tuple[list[NewFinding], int]:
    """A tool's masked output -> (findings, requests sent). Tools without a reader: none.

    A tool with no reader still keeps its masked output on the tool run.
    """
    reader = READERS.get(str(tool).lower())
    return reader(output) if reader else ([], 0)


def save_findings(
    db: Db, mask: MaskSecrets, assessment_id: UUID, run: ToolRun, new: list[NewFinding]
) -> list[Finding]:
    """One finding per dedupe_key in the assessment. Found again: add this run as a source."""
    if new:
        assessment_repo.lock(db, assessment_id)  # RCX codes are given out one run at a time
    saved = []
    for item in new:
        finding = finding_repo.get_by_dedupe_key(db, assessment_id, item.dedupe_key)
        if finding is None:
            finding = _new_finding(db, mask, assessment_id, item)
        finding_repo.add_source(db, finding.finding_id, run.tool_run_id)
        for proof in item.evidence:
            content, _ = mask(proof.content)
            location, _ = mask(proof.location)
            finding_repo.add(
                db,
                Evidence(
                    kind=proof.kind,
                    content=content,
                    location=location,
                    finding_id=finding.finding_id,
                    tool_run_id=run.tool_run_id,
                ),
            )
        saved.append(finding)
    return saved


def list_findings(db: Db, assessment_id: UUID) -> list[FindingOut]:
    if assessment_repo.get(db, assessment_id) is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    return [_finding_out(db, row) for row in finding_repo.list_by_assessment(db, assessment_id)]


def _new_finding(db: Db, mask: MaskSecrets, assessment_id: UUID, item: NewFinding) -> Finding:
    number = finding_repo.count_in_assessment(db, assessment_id) + 1
    finding = Finding(
        code=f"RCX-{number:03d}",
        title=mask(item.title)[0],
        target=mask(item.target)[0],
        description=mask(item.description)[0],
        severity_status=item.severity,
        cwe_ids=item.cwe_ids,
        owasp_id=item.owasp_id,
        cve_ids=item.cve_ids,
        remediation=item.remediation,
        dedupe_key=item.dedupe_key,
        assessment_id=assessment_id,
    )
    finding_repo.add(db, finding)
    return finding


def _finding_out(db: Db, row: Finding) -> FindingOut:
    out = FindingOut.model_validate(row, from_attributes=True)
    out.source_tool_run_ids = finding_repo.source_run_ids(db, row.finding_id)
    out.evidence = [
        EvidenceOut.model_validate(evidence, from_attributes=True)
        for evidence in finding_repo.list_evidence(db, row.finding_id)
    ]
    return out
