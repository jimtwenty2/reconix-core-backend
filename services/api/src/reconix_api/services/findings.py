"""Findings from a tool run (dedupe, sources, masked evidence): save, read and review."""

import asyncio
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_ai.harness.catalog import canonical, is_known_tool
from reconix_api.core.errors import ApiError
from reconix_api.core.finding_memory import FindingMemory, MemoryUnavailable
from reconix_api.core.interfaces import (
    AgentRequest,
    AgentTask,
    Interfaces,
    Operator,
    WriteAudit,
)
from reconix_api.core.masking import MaskSecrets, mask_output
from reconix_api.findings import json_mapping
from reconix_api.findings import nmap as nmap_findings
from reconix_api.findings import osv as osv_findings
from reconix_api.findings import sarif as sarif_findings
from reconix_api.findings.shape import NewFinding
from reconix_api.models import Evidence, Finding, ToolRun, ValidationRun
from reconix_api.models.enums import (
    AgentRunStatus,
    FindingStatus,
    ToolRunStatus,
    ValidationStatus,
)
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import findings as finding_repo
from reconix_api.schemas.findings import (
    EvidenceOut,
    FindingFilters,
    FindingOut,
    FindingReview,
    ValidationRunIn,
    ValidationRunOut,
)
from reconix_api.services.audit import audit

logger = logging.getLogger(__name__)
MEMORY_TIMEOUT_SECONDS = 30  # one embedding and one Qdrant write; the review is already saved

# One reader per Kali tool name: masked output -> (findings, requests sent).
# JSON tools share one reader through their mapping; the rest have their own.
READERS: dict[str, Callable[[str], tuple[list[NewFinding], int]]] = {
    "nmap": nmap_findings.read,
    "osv_scanner": osv_findings.read,
    # ZAP's report is SARIF (zap_report, template sarif-json). Core's "ZAP" is zap_scan.
    "zap_scan": partial(sarif_findings.read, "zap_alert"),
    **{name: partial(json_mapping.read, rule) for name, rule in json_mapping.MAPPINGS.items()},
}

# Control characters, except tab and newline. A scanned host can put terminal escape
# codes in a banner or hostname; they must not reach the TUI, the web or the AI.
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def parse_run(tool: str, output: str) -> tuple[list[NewFinding], int]:
    """A tool's masked output -> (findings, requests sent). Tools without a reader: none.

    Looked up by the catalog name, so "ZAP", "zap" and "zap_scan" find the same reader.
    A tool with no reader still keeps its masked output on the tool run.
    """
    reader = READERS.get(canonical(str(tool)))
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
            content, _ = mask_output(mask, CONTROL.sub("", proof.content))
            location = _clean(mask, proof.location)
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


def list_findings(db: Db, filters: FindingFilters | None = None) -> list[FindingOut]:
    """Every finding, or one assessment's; each filter given must match."""
    filters = filters or FindingFilters()
    if filters.tool is not None and not is_known_tool(filters.tool):
        raise ApiError(422, "UNKNOWN_TOOL", "This tool is not in the Kali catalog.")
    if filters.assessment_id is not None and assessment_repo.get(db, filters.assessment_id) is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    rows = finding_repo.list_matching(db, **filters.model_dump())
    return [_finding_out(db, row) for row in rows]


def read_finding(db: Db, finding_id: UUID) -> FindingOut:
    return _finding_out(db, _get_finding(db, finding_id))


def review_finding(
    db: Db, write_audit: WriteAudit, operator: Operator, finding_id: UUID, body: FindingReview
) -> FindingOut:
    """OPEN, FALSE_POSITIVE or FIXED, with who decided and when."""
    finding = _get_finding(db, finding_id, lock=True)
    before = finding.finding_status
    finding.finding_status = body.finding_status
    finding.reviewed_by = operator.actor
    finding.reviewed_at = datetime.now(UTC)
    db.commit()
    details = {"finding_id": str(finding_id), "from": before, "to": body.finding_status}
    audit(write_audit, "FINDING_REVIEWED", operator, finding.assessment_id, details)
    return _finding_out(db, finding)


POC = "poc"


async def check_finding(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    finding_id: UUID,
    body: ValidationRunIn,
) -> ValidationRunOut:
    """Confirm a finding from a completed PoC tool run. The AI reads that run's real
    (masked) output and sets the verdict; the finding takes it as its validation_status.
    No person sets the verdict by hand."""
    # Local imports: findings is imported by tool_runs, so a top-level import of these
    # (which route back through actions -> tool_runs -> findings) would be a cycle.
    from reconix_api.services import agent_runs, plans
    from reconix_api.services.analysis import finding_input

    finding = _get_finding(db, finding_id)
    assessment_id, code = finding.assessment_id, finding.code
    tool_run = finding_repo.get_tool_run(db, body.tool_run_id)
    # A run from another assessment is treated as not found, so nothing leaks across them.
    if tool_run is None or finding_repo.tool_run_assessment(db, body.tool_run_id) != assessment_id:
        raise ApiError(404, "TOOL_RUN_NOT_FOUND", "No tool run with this id for this finding.")
    if tool_run.tool_run_status != ToolRunStatus.COMPLETED:
        raise ApiError(422, "TOOL_RUN_NOT_COMPLETED", "The PoC tool run has not completed.")

    scope = plans.approved_scope(interfaces, assessment_id)
    run = agent_runs.new_agent_run(db, operator, assessment_id, task="VALIDATE")
    db.commit()
    try:
        provider, model = agent_runs.agent_provider(db, run)
        response = await agent_runs.ask_agent(
            db,
            interfaces,
            AgentRequest(
                task=AgentTask.VALIDATE,
                assessment_id=assessment_id,
                agent_run_id=run.agent_run_id,
                provider=provider,
                model=model,
                scope=scope,
                findings=[finding_input(finding)],
                tool_results=[tool_run.output_masked or ""],
            ),
        )
    except Exception as error:
        agent_runs.fail(db, interfaces, operator, run, error)
        raise
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.COMPLETED, {"finding": code})

    verdict = ValidationStatus(response.validation_status or ValidationStatus.INCONCLUSIVE)
    finding = _get_finding(db, finding_id, lock=True)
    validation = ValidationRun(
        method=POC,
        validation_status=verdict,
        reason=mask(response.validation_reason)[0] if response.validation_reason else None,
        reviewed_by="agent",  # the verdict is the AI's, not a person's
        reviewed_at=datetime.now(UTC),
        finding_id=finding_id,
        tool_run_id=body.tool_run_id,
    )
    finding_repo.add(db, validation)
    finding.validation_status = verdict
    db.commit()
    details = {
        "finding_id": str(finding_id),
        "validation_run_id": str(validation.validation_run_id),
        "validation_status": verdict,
        "method": POC,
        "tool_run_id": str(body.tool_run_id),
    }
    audit(interfaces.write_audit, "FINDING_CHECKED", operator, assessment_id, details)
    return ValidationRunOut.model_validate(validation, from_attributes=True)


def list_validation_runs(db: Db, finding_id: UUID) -> list[ValidationRunOut]:
    _get_finding(db, finding_id)
    return [
        ValidationRunOut.model_validate(run, from_attributes=True)
        for run in finding_repo.list_validation_runs(db, finding_id)
    ]


async def update_memory(memory: FindingMemory, finding: FindingOut) -> None:
    """A finding a person reviewed as OPEN or FIXED is accepted and remembered by the AI;
    FALSE_POSITIVE forgets it. Runs after the review is saved and answered: a memory that
    is down (Qdrant or the embedding model) is logged by its code and never undoes or
    blocks a person's decision. Any other error is a bug and is raised.

    shortcut: a failed update, or two reviews of one finding at the same moment, can leave
    the memory behind the database; add a re-sync from the findings table when CHAT reads it.
    """
    accepted = finding.finding_status != FindingStatus.FALSE_POSITIVE
    code = None
    try:
        await asyncio.wait_for(memory(finding, accepted), MEMORY_TIMEOUT_SECONDS)
    except MemoryUnavailable as error:
        code = error.code
    except TimeoutError:
        code = "TIMEOUT"
    if code is not None:
        logger.warning("Finding %s is reviewed; the AI memory is down: %s", finding.code, code)


def read_evidence(db: Db, evidence_id: UUID) -> EvidenceOut:
    """Masked evidence. The raw value needs a disclosure approval (not built yet)."""
    evidence = finding_repo.get_evidence(db, evidence_id)
    if evidence is None:
        raise ApiError(404, "EVIDENCE_NOT_FOUND", "No evidence with this id.")
    return EvidenceOut.model_validate(evidence, from_attributes=True)


def _get_finding(db: Db, finding_id: UUID, lock: bool = False) -> Finding:
    finding = finding_repo.get(db, finding_id, lock=lock)
    if finding is None:
        raise ApiError(404, "FINDING_NOT_FOUND", "No finding with this id.")
    return finding


def _new_finding(db: Db, mask: MaskSecrets, assessment_id: UUID, item: NewFinding) -> Finding:
    number = finding_repo.count_in_assessment(db, assessment_id) + 1
    finding = Finding(
        code=f"RCX-{number:03d}",
        title=_clean(mask, item.title),
        target=_clean(mask, item.target),
        description=_clean(mask, item.description),
        severity_status=item.severity,
        cwe_ids=item.cwe_ids,
        owasp_id=item.owasp_id,
        cve_ids=item.cve_ids,
        remediation=_clean(mask, item.remediation) if item.remediation else None,
        dedupe_key=item.dedupe_key,
        assessment_id=assessment_id,
    )
    finding_repo.add(db, finding)
    return finding


def _clean(mask: MaskSecrets, text: str) -> str:
    """Text the scanned host or the tool chose: control characters removed, then masked."""
    return mask(CONTROL.sub("", text))[0]


def _finding_out(db: Db, row: Finding) -> FindingOut:
    out = FindingOut.model_validate(row, from_attributes=True)
    runs = finding_repo.sources(db, row.finding_id)
    out.source_tool_run_ids = [tool_run_id for tool_run_id, _ in runs]
    out.tools = sorted({tool for _, tool in runs})
    out.evidence = [
        EvidenceOut.model_validate(evidence, from_attributes=True)
        for evidence in finding_repo.list_evidence(db, row.finding_id)
    ]
    checks = finding_repo.list_validation_runs(db, row.finding_id)
    if checks:
        out.latest_validation = ValidationRunOut.model_validate(checks[0], from_attributes=True)
    return out
