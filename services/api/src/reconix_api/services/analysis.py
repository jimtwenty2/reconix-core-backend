"""Analysis: the agent writes the 8-part analysis of each OPEN finding.

The ANALYZE step fills each finding's plain-language explanation, impact and remediation
(empty until now), so the operator reads an analysis instead of only the raw tool evidence.
The verdict a person owns is left alone: the finding status (OPEN / FALSE_POSITIVE / FIXED)
and the severity are never set here, only the explanatory fields and a missing CVSS score.
The full suggestion (related findings, a next step, "unsure") is still kept in the run
(agent_runs.plan) and returned. Changing a finding's status stays PATCH /findings/{id}.
"""

from decimal import Decimal
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    AgentRequest,
    AgentTask,
    ApprovedScope,
    FindingAnalysis,
    FindingInput,
    Interfaces,
    Operator,
)
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import AgentRun, Evidence, Finding
from reconix_api.models.enums import AgentRunStatus, FindingStatus
from reconix_api.repositories import findings as findings_repo
from reconix_api.schemas.agent_runs import AnalysisOut
from reconix_api.schemas.findings import confidence_of
from reconix_api.services import actions, agent_runs, plans

GROUP_SIZE = 10  # the agent analyzes at most 10 findings in one ask
TOOL_OUTPUTS = 3  # the agent reads the newest 3 outputs; evidence must come from them
SUMMARY_KIND = "analysis_summary"  # the AI's plain reading of the evidence, kept as evidence


async def analyze(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    assessment_id: UUID,
    finding_ids: list[UUID] | None = None,
) -> AnalysisOut:
    actions.ensure_can_act(db, assessment_id)
    # finding_ids limits the analysis to those findings (per-step analysis, as each step
    # finds them); omitted, it analyzes every OPEN finding (the end-of-run batch).
    wanted = set(finding_ids) if finding_ids else None
    findings = [
        finding
        for finding in findings_repo.list_by_assessment(db, assessment_id)
        if finding.finding_status == FindingStatus.OPEN
        and (wanted is None or finding.finding_id in wanted)
    ]
    if not findings:
        raise ApiError(422, "NO_FINDINGS", "This assessment has no OPEN findings to analyze.")
    scope = plans.approved_scope(interfaces, assessment_id)
    run = agent_runs.new_agent_run(db, operator, assessment_id, task="ANALYZE")
    db.commit()
    try:
        return await analyze_in_groups(db, interfaces, mask, operator, run, scope, findings)
    except Exception as error:
        agent_runs.fail(db, interfaces, operator, run, error)
        raise


async def analyze_in_groups(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    run: AgentRun,
    scope: ApprovedScope,
    findings: list[Finding],
) -> AnalysisOut:
    summaries: list[str] = []
    analysis: list[FindingAnalysis] = []
    provider, model = agent_runs.agent_provider(db, run)
    for start in range(0, len(findings), GROUP_SIZE):
        group = findings[start : start + GROUP_SIZE]
        outputs = findings_repo.source_outputs(db, [f.finding_id for f in group], TOOL_OUTPUTS)
        response = await agent_runs.ask_agent(
            db,
            interfaces,
            AgentRequest(
                task=AgentTask.ANALYZE,
                assessment_id=run.assessment_id,
                agent_run_id=run.agent_run_id,
                provider=provider,
                model=model,
                scope=scope,
                findings=[finding_input(db, finding) for finding in group],
                tool_results=outputs,
            ),
        )
        summaries.append(mask(response.analysis_summary)[0])
        analysis.extend(masked(item, mask) for item in response.analysis)
    summary = "\n\n".join(text for text in summaries if text)
    apply_analysis(db, findings, analysis)
    run.plan = {
        "task": "ANALYZE",
        "summary": summary,
        "analysis": [item.model_dump(mode="json") for item in analysis],
    }
    agent_runs.end(
        db, interfaces, operator, run, AgentRunStatus.COMPLETED, {"findings": str(len(analysis))}
    )
    return AnalysisOut(agent_run=agent_runs.agent_run_out(run), summary=summary, analysis=analysis)


def apply_analysis(db: Db, findings: list[Finding], analysis: list[FindingAnalysis]) -> None:
    """Write the agent's analysis onto each finding, matched by code. The texts are already
    masked (see `masked`). Only the explanatory fields a reader needs are set — the plain
    explanation, the impact and the remediation — plus a CVSS score when the finding has
    none. The status and severity, which a person owns, are left untouched. The plain reading
    of the evidence is kept as an `analysis_summary` evidence row (see `save_evidence_summary`),
    so a reader sees prose beside the raw proof instead of a JSON blob."""
    by_code = {finding.code: finding for finding in findings}
    for item in analysis:
        finding = by_code.get(item.code)
        if finding is None:
            continue
        if item.explanation:
            finding.description = item.explanation
        if item.impact:
            finding.impact = item.impact
        if item.remediation:
            finding.remediation = item.remediation
        if item.cvss_score is not None and finding.cvss_score is None:
            finding.cvss_score = Decimal(str(item.cvss_score))
        if item.evidence_summary:
            save_evidence_summary(db, finding, item.evidence_summary)


def save_evidence_summary(db: Db, finding: Finding, summary: str) -> None:
    """Keep the AI's plain reading of the evidence as one `analysis_summary` evidence row,
    replacing any earlier one so a re-analysis never stacks up duplicates. It hangs off the
    finding's own source tool run (the proof it reads from), so no new column is needed."""
    for row in findings_repo.list_evidence(db, finding.finding_id):
        if row.kind == SUMMARY_KIND:
            row.content = summary
            return
    sources = findings_repo.sources(db, finding.finding_id)
    if not sources:  # a finding always comes from a tool run, but never guess one if it does not
        return
    tool_run_id, _ = sources[0]
    findings_repo.add(
        db,
        Evidence(
            kind=SUMMARY_KIND,
            content=summary,
            finding_id=finding.finding_id,
            tool_run_id=tool_run_id,
        ),
    )


def masked(item: FindingAnalysis, mask: MaskSecrets) -> FindingAnalysis:
    """Every text the agent wrote, masked again before it is saved or returned."""
    texts = ("explanation", "evidence", "evidence_summary", "impact", "remediation", "unsure")
    update = {name: mask(getattr(item, name))[0] for name in texts}
    step = item.next_step
    if step is not None:
        update["next_step"] = step.model_copy(
            update={
                "target": mask(step.target)[0],
                "arguments": [mask(argument)[0] for argument in step.arguments],
            }
        )
    return item.model_copy(update=update)


def finding_input(db: Db, finding: Finding) -> FindingInput:
    tools = [tool for _, tool in findings_repo.sources(db, finding.finding_id)]
    confidence = confidence_of(
        finding.validation_status, finding.finding_status, finding.severity_status, tools
    )
    return FindingInput(
        code=finding.code,
        title=finding.title,
        target=finding.target,
        description=finding.description,
        severity_status=finding.severity_status,
        finding_status=finding.finding_status,
        cvss_score=float(finding.cvss_score) if finding.cvss_score is not None else None,
        cwe_ids=finding.cwe_ids,
        owasp_id=finding.owasp_id,
        cve_ids=finding.cve_ids,
        confidence=str(confidence),
    )
