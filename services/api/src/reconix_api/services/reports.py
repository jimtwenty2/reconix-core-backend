"""Reports: a locked copy -> the agent writes the text -> 3 files -> review sign-off -> download.

The locked copy (findings, counts, tool runs and how each was approved) is made
by the API, masked, and saved with its SHA-256 hash; the agent only writes the
executive summary and the methodology. A report is GENERATING, then READY with
its files, or FAILED. Its files can be downloaded only after a person approved
its `review` approval, and only for the exact copy that was reviewed.
"""

import asyncio
import hashlib
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core import report_files
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    AgentRequest,
    AgentTask,
    FindingInput,
    Interfaces,
    Operator,
    ReportInput,
    RiskLevel,
    ToolRunInput,
    WriteAudit,
)
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import Approval, Assessment, Report
from reconix_api.models.enums import (
    AgentRunStatus,
    ApprovalStatus,
    FindingStatus,
    ReportStatus,
)
from reconix_api.repositories import actions as action_repo
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import findings as findings_repo
from reconix_api.repositories import reports as report_repo
from reconix_api.repositories import scopes as scope_repo
from reconix_api.schemas.reports import ReportFormat, ReportOut
from reconix_api.services import agent_runs, analysis, plans
from reconix_api.services.approvals import expires_at, snapshot_hash
from reconix_api.services.audit import audit

STALE_MINUTES = 10  # a report still GENERATING after this was cut off

# ---------------------------------------------------------------------------
# Create: locked copy -> GENERATING -> agent text -> files -> READY (or FAILED)
# ---------------------------------------------------------------------------


async def create_report(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    assessment_id: UUID,
) -> ReportOut:
    assessment = assessment_repo.get_for_update(db, assessment_id)  # one version at a time
    if assessment is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    manifest = scope_repo.get_approved(db, assessment_id)
    if manifest is None:
        raise ApiError(409, "SCOPE_NOT_APPROVED", "This assessment has no approved scope.")
    fail_stuck_reports(db, interfaces, operator, assessment_id)
    locked = locked_copy(db, assessment_id, mask)
    snapshot = locked.model_dump(mode="json")
    report = Report(
        version=report_repo.next_version(db, assessment_id),
        snapshot=snapshot,
        snapshot_hash=snapshot_hash(snapshot),
        generated_by=operator.actor,
        assessment_id=assessment_id,
        manifest_id=manifest.manifest_id,
    )
    report_repo.add(db, report)
    db.commit()
    folder = report_folder(settings, assessment, report)
    run = None
    try:  # from here on, any end (an error, a cancelled request) leaves the report FAILED
        audit(
            interfaces.write_audit,
            "REPORT_REQUESTED",
            operator,
            assessment_id,
            {"report_id": str(report.report_id), "version": str(report.version)},
        )
        scope = plans.approved_scope(interfaces, assessment_id)
        run = agent_runs.new_agent_run(db, operator, assessment_id, task="REPORT")
        db.commit()
        response = await interfaces.ask_agent(
            AgentRequest(
                task=AgentTask.REPORT,
                assessment_id=assessment_id,
                agent_run_id=run.agent_run_id,
                scope=scope,
                report=locked,
            )
        )
        summary = mask(response.executive_summary or "")[0]
        methodology = mask(response.methodology or "")[0]
        meta = report_meta(assessment, report)
        # WeasyPrint and the file writes are slow and blocking: off the event loop.
        files = await asyncio.to_thread(report_files.render, snapshot, summary, methodology, meta)
        exports = await asyncio.to_thread(save_files, folder, files)
    except BaseException as error:
        report_failed(db, interfaces, operator, report, error, folder)
        if run is not None:
            agent_runs.fail(db, interfaces, operator, run, error)
        raise
    report.exports = exports
    report.executive_summary = summary
    report.methodology = methodology
    report.report_status = ReportStatus.READY
    report.generated_at = datetime.now(UTC)
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.COMPLETED, {"task": "REPORT"})
    audit(
        interfaces.write_audit,
        "REPORT_READY",
        operator,
        assessment_id,
        {"report_id": str(report.report_id), "version": str(report.version)},
    )
    return report_out(db, report)


def locked_copy(db: Db, assessment_id: UUID, mask: MaskSecrets) -> ReportInput:
    """What the report says, frozen: every finding but FALSE_POSITIVE, the counts made
    here (never by the model), and each tool run with how it was approved. Masked."""
    findings = [
        masked_finding(analysis.finding_input(finding), mask)
        for finding in findings_repo.list_by_assessment(db, assessment_id)
        if finding.finding_status != FindingStatus.FALSE_POSITIVE
    ]
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity_status] = counts.get(finding.severity_status, 0) + 1
    tool_runs = [
        ToolRunInput(
            tool=action.tool,
            target=mask(action.target)[0],
            args=[mask(argument)[0] for argument in action.args],
            risk_level=action.risk_level or RiskLevel.HIGH,  # unrated counts as the worst
            tool_run_status=str(run.tool_run_status),
            approval_check=approval_check(db, action, run),
            started_at=run.started_at,
            finished_at=run.finished_at,
        )
        for run, action in action_repo.tool_runs_in_assessment(db, assessment_id)
    ]
    return ReportInput(findings=findings, severity_counts=counts, tool_runs=tool_runs)


def approval_check(db: Db, action: Any, run: Any) -> str:
    """NOT_REQUIRED for a LOW run; APPROVED when the run used an approved approval;
    MISSING for a MEDIUM or HIGH run without one, which the report must name."""
    if action.risk_level == RiskLevel.LOW:
        return "NOT_REQUIRED"
    approval = approval_repo.get(db, run.approval_id) if run.approval_id else None
    if approval is not None and approval.approval_status == ApprovalStatus.APPROVED:
        return "APPROVED"
    return "MISSING"


def masked_finding(finding: FindingInput, mask: MaskSecrets) -> FindingInput:
    texts = ("title", "target", "description")
    return finding.model_copy(update={name: mask(getattr(finding, name))[0] for name in texts})


def report_meta(assessment: Assessment, report: Report) -> dict[str, str]:
    return {
        "title": f"Reconix report {assessment.engagement_code}",
        "Assessment": assessment.engagement_code,
        "Version": str(report.version),
        "Snapshot hash (SHA-256)": report.snapshot_hash,
        "Generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    }


def save_files(folder: Path, files: dict[str, bytes]) -> dict[str, str]:
    """Writes report.<ext> for each format. Returns format -> path, and
    "<format>_SHA256" -> the file's hash, which the review signs and download checks."""
    folder.mkdir(parents=True, exist_ok=True)
    exports = {}
    for name, content in files.items():
        path = folder / f"report.{report_files.FORMATS[name]}"
        path.write_bytes(content)
        exports[name] = str(path)
        exports[f"{name}_SHA256"] = hashlib.sha256(content).hexdigest()
    return exports


def report_folder(settings: Settings, assessment: Assessment, report: Report) -> Path:
    """reports_dir/<assessment code>/v<version>. The code is made by the server."""
    return reports_root(settings) / assessment.engagement_code / f"v{report.version}"


def reports_root(settings: Settings) -> Path:
    return Path(settings.reports_dir).resolve()


def fail_stuck_reports(
    db: Db, interfaces: Interfaces, operator: Operator, assessment_id: UUID
) -> None:
    """A report still GENERATING after STALE_MINUTES was cut off (e.g. the API stopped)."""
    cutoff = datetime.now(UTC) - timedelta(minutes=STALE_MINUTES)
    for report in report_repo.generating_before(db, assessment_id, cutoff):
        report.report_status = ReportStatus.FAILED
        db.commit()
        audit(
            interfaces.write_audit,
            "REPORT_FAILED",
            operator,
            assessment_id,
            {"report_id": str(report.report_id), "code": "REPORT_CUT_OFF"},
        )


def report_failed(
    db: Db,
    interfaces: Interfaces,
    operator: Operator,
    report: Report,
    error: BaseException,
    folder: Path,
) -> None:
    db.rollback()
    report.report_status = ReportStatus.FAILED
    db.commit()
    shutil.rmtree(folder, ignore_errors=True)  # no half-written files are left
    code = error.code if isinstance(error, ApiError) else "UNEXPECTED_ERROR"
    audit(
        interfaces.write_audit,
        "REPORT_FAILED",
        operator,
        report.assessment_id,
        {"report_id": str(report.report_id), "code": code},
    )


# ---------------------------------------------------------------------------
# Review sign-off: a `review` approval for the exact locked copy
# ---------------------------------------------------------------------------


def request_review(
    db: Db, write_audit: WriteAudit, operator: Operator, report_id: UUID, ttl_minutes: int
) -> Approval:
    """A `review` approval for this READY report; decided through /approvals/{id}."""
    report = get(db, report_id, lock=True)
    if report.report_status != ReportStatus.READY:
        raise ApiError(
            409,
            "REPORT_NOT_READY",
            "Only a READY report can be signed off.",
            {"report_status": report.report_status},
        )
    review = report_repo.review_for(db, report_id)
    expire_lapsed_review(db, write_audit, operator, report, review, ttl_minutes)
    if review is not None and review.approval_status in (
        ApprovalStatus.PENDING,
        ApprovalStatus.APPROVED,
    ):
        raise ApiError(
            409,
            "REVIEW_EXISTS",
            "This report already has an open or approved review.",
            {"approval_id": str(review.approval_id), "approval_status": review.approval_status},
        )
    approval = approval_repo.add(
        db,
        Approval(
            kind="review",
            subject_snapshot={
                "report_id": str(report.report_id),
                "version": report.version,
                "snapshot_hash": report.snapshot_hash,
                "files": file_hashes(report),
            },
            subject_hash=review_hash(report),
            report_id=report.report_id,
        ),
    )
    db.commit()
    audit(
        write_audit,
        "APPROVAL_REQUESTED",
        operator,
        report.assessment_id,
        {"report_id": str(report.report_id), "approval_id": str(approval.approval_id)},
    )
    return approval


def approve_review(db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval) -> None:
    """Called from services/decisions.py. The sign-off is for exactly what was reviewed:
    if the copy, the texts or a file changed since, it is refused. Approving uses it."""
    report = get(db, approval.report_id, lock=True)
    if review_hash(report) != approval.subject_hash:
        raise ApiError(409, "REPORT_CHANGED", "The report changed after the review was asked.")
    now = datetime.now(UTC)
    approval.approval_status = ApprovalStatus.APPROVED
    approval.decided_by = operator.actor
    approval.decided_at = now
    approval.consumed_at = now  # single use: the sign-off is its one use
    db.commit()
    audit(
        write_audit,
        "APPROVAL_GRANTED",
        operator,
        report.assessment_id,
        {"report_id": str(report.report_id), "approval_id": str(approval.approval_id)},
    )


def review_hash(report: Report) -> str:
    """SHA-256 over what a person signs off: the locked copy (hashed again from the saved
    snapshot, not read from its column), the two texts and the hash of each file."""
    return snapshot_hash(
        {
            "snapshot": snapshot_hash(report.snapshot),
            "executive_summary": report.executive_summary,
            "methodology": report.methodology,
            "files": file_hashes(report),
        }
    )


def file_hashes(report: Report) -> dict[str, str]:
    return {name: report.exports.get(f"{name}_SHA256", "") for name in report_files.FORMATS}


def expire_lapsed_review(
    db: Db,
    write_audit: WriteAudit,
    operator: Operator,
    report: Report,
    review: Approval | None,
    ttl_minutes: int,
) -> None:
    """A review still PENDING past its 30 minutes is EXPIRED, so a new one can be asked."""
    if review is None or review.approval_status != ApprovalStatus.PENDING:
        return
    if datetime.now(UTC) < expires_at(review.requested_at, ttl_minutes):
        return
    review.approval_status = ApprovalStatus.EXPIRED
    db.commit()
    audit(
        write_audit,
        "APPROVAL_EXPIRED",
        operator,
        report.assessment_id,
        {"report_id": str(report.report_id), "approval_id": str(review.approval_id)},
    )


def reject_review(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval, reason: str | None
) -> None:
    report = get(db, approval.report_id)
    approval.approval_status = ApprovalStatus.REJECTED
    approval.decided_by = operator.actor
    approval.decided_at = datetime.now(UTC)
    approval.reason = reason
    db.commit()
    audit(
        write_audit,
        "APPROVAL_REJECTED",
        operator,
        report.assessment_id,
        {"report_id": str(report.report_id), "approval_id": str(approval.approval_id)},
    )


# ---------------------------------------------------------------------------
# Read and download
# ---------------------------------------------------------------------------


def list_reports(db: Db, assessment_id: UUID) -> list[ReportOut]:
    if assessment_repo.get(db, assessment_id) is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    return [report_out(db, report) for report in report_repo.list_by_assessment(db, assessment_id)]


def read_report(db: Db, report_id: UUID) -> ReportOut:
    return report_out(db, get(db, report_id))


def download(
    db: Db, settings: Settings, report_id: UUID, file_format: ReportFormat
) -> tuple[Path, str, str]:
    """(path, media type, file name) of a READY, signed-off report's file, checked to be
    inside reports_dir and to be the exact file that was signed off."""
    report = get(db, report_id)
    if report.report_status != ReportStatus.READY:
        raise ApiError(409, "REPORT_NOT_READY", "The report is not READY.")
    if not signed_off(report_repo.review_for(db, report_id)):
        raise ApiError(409, "REPORT_NOT_SIGNED_OFF", "A person must approve the review first.")
    path = Path(report.exports.get(file_format, "")).resolve()
    inside = path.is_relative_to(reports_root(settings))
    if not report.exports.get(file_format) or not inside or not path.is_file():
        raise ApiError(404, "REPORT_FILE_MISSING", f"The {file_format} file is missing.")
    if hashlib.sha256(path.read_bytes()).hexdigest() != file_hashes(report)[file_format]:
        raise ApiError(
            409, "REPORT_FILE_CHANGED", f"The {file_format} file changed after the sign-off."
        )
    assessment = assessment_repo.get(db, report.assessment_id)
    extension = report_files.FORMATS[file_format]
    name = f"{assessment.engagement_code}-v{report.version}.{extension}"
    return path, report_files.MEDIA_TYPES[file_format], name


def report_out(db: Db, report: Report) -> ReportOut:
    review = report_repo.review_for(db, report.report_id)
    return ReportOut(
        report_id=report.report_id,
        version=report.version,
        report_status=report.report_status,
        executive_summary=report.executive_summary,
        methodology=report.methodology,
        snapshot_hash=report.snapshot_hash,
        formats=[name for name in report_files.FORMATS if name in report.exports],
        generated_by=report.generated_by,
        generated_at=report.generated_at,
        created_at=report.created_at,
        assessment_id=report.assessment_id,
        review_approval_id=review.approval_id if review else None,
        review_status=review.approval_status if review else None,
        signed_off=signed_off(review),
    )


def signed_off(review: Approval | None) -> bool:
    return review is not None and review.approval_status == ApprovalStatus.APPROVED


def get(db: Db, report_id: UUID, lock: bool = False) -> Report:
    report = report_repo.get(db, report_id, lock=lock)
    if report is None:
        raise ApiError(404, "REPORT_NOT_FOUND", "No report with this id.")
    return report
