"""Analysis: the agent suggests the 8-part analysis of each OPEN finding.

Suggestions only. They are saved in the run (agent_runs.plan) and returned; no
finding changes until a person accepts a suggestion with PATCH /findings/{id}.
"""

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
from reconix_api.models import AgentRun, Finding
from reconix_api.models.enums import AgentRunStatus, FindingStatus
from reconix_api.repositories import findings as findings_repo
from reconix_api.schemas.agent_runs import AnalysisOut
from reconix_api.services import actions, agent_runs, plans

GROUP_SIZE = 10  # the agent analyzes at most 10 findings in one ask
TOOL_OUTPUTS = 3  # the agent reads the newest 3 outputs; evidence must come from them


async def analyze(
    db: Db, interfaces: Interfaces, mask: MaskSecrets, operator: Operator, assessment_id: UUID
) -> AnalysisOut:
    actions.ensure_can_act(db, assessment_id)
    findings = [
        finding
        for finding in findings_repo.list_by_assessment(db, assessment_id)
        if finding.finding_status == FindingStatus.OPEN
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
                findings=[finding_input(finding) for finding in group],
                tool_results=outputs,
            ),
        )
        summaries.append(mask(response.analysis_summary)[0])
        analysis.extend(masked(item, mask) for item in response.analysis)
    summary = "\n\n".join(text for text in summaries if text)
    run.plan = {
        "task": "ANALYZE",
        "summary": summary,
        "analysis": [item.model_dump(mode="json") for item in analysis],
    }
    agent_runs.end(
        db, interfaces, operator, run, AgentRunStatus.COMPLETED, {"findings": str(len(analysis))}
    )
    return AnalysisOut(agent_run=agent_runs.agent_run_out(run), summary=summary, analysis=analysis)


def masked(item: FindingAnalysis, mask: MaskSecrets) -> FindingAnalysis:
    """Every text the agent wrote, masked again before it is saved or returned."""
    texts = ("explanation", "evidence", "impact", "remediation", "unsure")
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


def finding_input(finding: Finding) -> FindingInput:
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
    )
