"""Findings from a tool run (dedupe, sources, masked evidence): save, read and review."""

import asyncio
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.disclosure import HiddenValue
from reconix_api.core.errors import ApiError
from reconix_api.core.finding_memory import FindingMemory, MemoryUnavailable
from reconix_api.core.interfaces import Operator, ToolName, WriteAudit
from reconix_api.core.masking import MaskSecrets, mask_output
from reconix_api.findings import json_mapping
from reconix_api.findings import nmap as nmap_findings
from reconix_api.findings import osv as osv_findings
from reconix_api.findings import sarif as sarif_findings
from reconix_api.findings.shape import NewFinding
from reconix_api.models import Evidence, Finding, ToolRun, ValidationRun
from reconix_api.models.enums import FindingStatus
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
    # ZAP's report is SARIF (zap_report, template sarif-json).
    "zap": partial(sarif_findings.read, "zap_alert"),
    **{name: partial(json_mapping.read, rule) for name, rule in json_mapping.MAPPINGS.items()},
}

# Control characters, except tab and newline. A scanned host can put terminal escape
# codes in a banner or hostname; they must not reach the TUI, the web or the AI.
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def parse_run(tool: ToolName | str, output: str) -> tuple[list[NewFinding], int]:
    """A tool's masked output -> (findings, requests sent). Tools without a reader: none.

    A tool with no reader still keeps its masked output on the tool run.
    """
    reader = READERS.get(str(tool).lower())
    return reader(output) if reader else ([], 0)


# The real values behind one saved evidence's labels, for the disclosure vault.
KeptValues = tuple[UUID, list[HiddenValue]]


def save_findings(
    db: Db,
    mask: MaskSecrets,
    assessment_id: UUID,
    run: ToolRun,
    new: list[NewFinding],
    raw: list[NewFinding] | None = None,
) -> tuple[list[Finding], list[KeptValues]]:
    """One finding per dedupe_key in the assessment. Found again: add this run as a source.

    `new` comes from the masked output. `raw` is the same output parsed before masking (in
    memory only); it is used only to find the real value behind each label of the saved
    evidence, for a `disclosure` approval. Nothing from `raw` is saved here.
    """
    if new:
        assessment_repo.lock(db, assessment_id)  # RCX codes are given out one run at a time
    raw_proofs = _raw_proofs(new, raw)
    saved: list[Finding] = []
    kept: list[KeptValues] = []
    for item_no, item in enumerate(new):
        finding = finding_repo.get_by_dedupe_key(db, assessment_id, item.dedupe_key)
        if finding is None:
            finding = _new_finding(db, mask, assessment_id, item)
        finding_repo.add_source(db, finding.finding_id, run.tool_run_id)
        for proof_no, proof in enumerate(item.evidence):
            content, _ = mask_output(mask, CONTROL.sub("", proof.content))
            evidence = Evidence(
                kind=proof.kind,
                content=content,
                location=_clean(mask, proof.location),
                finding_id=finding.finding_id,
                tool_run_id=run.tool_run_id,
            )
            finding_repo.add(db, evidence)
            raw_proof = raw_proofs.get((item_no, proof_no))
            hidden = hidden_values(content, raw_proof) if raw_proof is not None else []
            if hidden:
                kept.append((evidence.evidence_id, hidden))
        saved.append(finding)
    return saved, kept


LABEL = re.compile(r"\[MASKED:(?P<kind>[a-z_]+)\]")


def hidden_values(masked: str, raw_proof: str) -> list[HiddenValue]:
    """The real value behind each label of a saved evidence, found by lining the masked
    text up with the same evidence from the raw output. The raw text first goes through
    the same shaping as the masked one (JSON written the same way, nmap's raw replies
    dropped), with nothing masked. If the two do not line up exactly: nothing is kept.
    """
    labels = list(LABEL.finditer(masked))
    if not labels:
        return []
    shaped, _ = mask_output(lambda text: (text, 0), CONTROL.sub("", raw_proof))
    pattern, last = "", 0
    for label in labels:
        if label.start() == last and last != 0:
            return []  # two labels side by side: no way to tell where one value ends
        pattern += re.escape(masked[last : label.start()]) + "(.+?)"
        last = label.end()
    match = re.fullmatch(pattern + re.escape(masked[last:]), shaped, re.DOTALL)
    if match is None:
        return []
    return [
        HiddenValue(index=index, kind=label["kind"], start=label.start(), value=match[index + 1])
        for index, label in enumerate(labels)
    ]


def _raw_proofs(new: list[NewFinding], raw: list[NewFinding] | None) -> dict[tuple[int, int], str]:
    """The raw evidence text for each (finding, evidence) position, only when both parses
    found the same findings with the same evidence in the same order."""
    if raw is None or len(raw) != len(new):
        return {}
    pairs: dict[tuple[int, int], str] = {}
    for item_no, (item, raw_item) in enumerate(zip(new, raw, strict=True)):
        if len(item.evidence) != len(raw_item.evidence):
            return {}
        for proof_no, (proof, raw_proof) in enumerate(
            zip(item.evidence, raw_item.evidence, strict=True)
        ):
            if proof.kind != raw_proof.kind:
                return {}
            pairs[(item_no, proof_no)] = raw_proof.content
    return pairs


def list_findings(db: Db, filters: FindingFilters | None = None) -> list[FindingOut]:
    """Every finding, or one assessment's; each filter given must match."""
    filters = filters or FindingFilters()
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


MANUAL_REVIEW = "manual_review"


def check_finding(
    db: Db,
    write_audit: WriteAudit,
    mask: MaskSecrets,
    operator: Operator,
    finding_id: UUID,
    body: ValidationRunIn,
) -> ValidationRunOut:
    """A person checked a finding by hand. The check is saved as a validation run, and
    the finding takes its result as its validation_status (the newest check wins)."""
    finding = _get_finding(db, finding_id, lock=True)
    run = ValidationRun(
        method=MANUAL_REVIEW,
        validation_status=body.validation_status,
        reason=mask(body.reason)[0] if body.reason else None,
        reviewed_by=operator.actor,
        reviewed_at=datetime.now(UTC),
        finding_id=finding_id,
    )
    finding_repo.add(db, run)
    finding.validation_status = body.validation_status
    db.commit()
    details = {
        "finding_id": str(finding_id),
        "validation_run_id": str(run.validation_run_id),
        "validation_status": body.validation_status,
        "method": MANUAL_REVIEW,
    }
    audit(write_audit, "FINDING_CHECKED", operator, finding.assessment_id, details)
    return ValidationRunOut.model_validate(run, from_attributes=True)


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
    """Masked evidence. A real value needs a disclosure approval (services/disclosures.py)."""
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
