"""Fake of ask_agent: plans one nmap step on the first allowed IP range, then waits.

CHAT answers the person's last message by repeating it, and never suggests a step.

ANALYZE gives back each finding unchanged, marked for a person to decide. Like the
real agent, it answers a resume with the person's decision and no new step, and gives
the same errors: only PLAN, SUGGEST, ANALYZE and CHAT, one decision per waiting run, and a
decision only for the action the run waits on. Any provider is called, as the real
ask_agent does with the run's own provider.
"""

from uuid import UUID

from reconix_api.core.errors import ApiError
from reconix_api.core.finding_memory import MemoryUnavailable
from reconix_api.core.interfaces import (
    Action,
    AgentRequest,
    AgentResponse,
    AgentTask,
    FindingAnalysis,
    FindingInput,
    OnPiece,
    PlanStep,
    RiskLevel,
    ToolName,
)
from reconix_api.schemas.findings import FindingOut

SUPPORTED_TASKS = {
    AgentTask.PLAN,
    AgentTask.SUGGEST,
    AgentTask.ANALYZE,
    AgentTask.REPORT,
    AgentTask.CHAT,
    AgentTask.VALIDATE,
}


class FakeAgent:
    def __init__(self) -> None:
        self.requests: list[AgentRequest] = []
        self.waiting: dict[UUID, tuple[UUID, Action]] = {}  # run -> (assessment, action)
        self.suggest: Action | None = None  # set by a test: the step the next plan suggests
        self.verdict = "CONFIRMED"  # set by a test: the VALIDATE verdict the fake returns
        self.down = False  # set by a test: the model is not running
        self.error: Exception | None = None  # set by a test: a bug, not an ApiError
        self.fail_after_pieces = False  # set by a test: a CHAT fails after it streamed

    async def ask_agent(
        self, request: AgentRequest, on_piece: OnPiece | None = None
    ) -> AgentResponse:
        """With on_piece, a CHAT answer is first sent one word at a time."""
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        if self.down:
            raise ApiError(503, "MODEL_UNAVAILABLE", "The RECONIX model could not answer.")
        if request.resume is not None:
            return self.resume(request)
        if request.task not in SUPPORTED_TASKS:
            raise ApiError(422, "TASK_NOT_SUPPORTED", f"The agent cannot do {request.task} yet.")
        if request.agent_run_id in self.waiting:
            raise ApiError(409, "RUN_IS_WAITING", "This run is waiting for a person to decide.")
        if request.task == AgentTask.ANALYZE:
            return self.analyze(request)
        if request.task == AgentTask.VALIDATE:
            return self.validate(request)
        if request.task == AgentTask.REPORT:
            return self.report(request)
        if request.task == AgentTask.CHAT:
            response = self.chat(request)
            if on_piece is not None:
                for word in response.text.split(" "):
                    await on_piece(word + " ")
            if self.fail_after_pieces:
                raise ApiError(503, "MODEL_UNAVAILABLE", "The model stopped half way.")
            return response
        return self.plan(request)

    def chat(self, request: AgentRequest) -> AgentResponse:
        person = [m.content_masked for m in request.messages if m.role == "user"]
        return AgentResponse(
            text=f"Fake answer to: {person[-1] if person else ''}",
            agent_run_id=request.agent_run_id,
        )

    def analyze(self, request: AgentRequest) -> AgentResponse:
        if not request.findings:
            raise ApiError(422, "NO_FINDINGS", "There are no findings to analyze.")
        return AgentResponse(
            text="Fake analysis.",
            analysis_summary="Fake analysis.",
            analysis=[unsure_analysis(finding) for finding in request.findings],
            agent_run_id=request.agent_run_id,
        )

    def validate(self, request: AgentRequest) -> AgentResponse:
        if len(request.findings) != 1:
            raise ApiError(422, "ONE_FINDING", "A validation judges exactly one finding.")
        if not any(result.strip() for result in request.tool_results):
            raise ApiError(
                422, "NO_TOOL_RESULT", "A validation needs the PoC tool output to judge."
            )
        finding = request.findings[0]
        return AgentResponse(
            text=f"Fake verdict {self.verdict} for {finding.code}.",
            validation_status=self.verdict,
            validation_reason=f"Fake PoC check of {finding.code}.",
            agent_run_id=request.agent_run_id,
        )

    def report(self, request: AgentRequest) -> AgentResponse:
        if request.report is None:
            raise ApiError(422, "NO_REPORT_DATA", "A report needs the locked copy of its data.")
        counts = ", ".join(f"{n} {level}" for level, n in request.report.severity_counts.items())
        return AgentResponse(
            text="Fake report.",
            executive_summary=f"Fake summary: {counts or 'no findings'}.",
            methodology=f"Fake methodology: {len(request.report.tool_runs)} tool runs.",
            agent_run_id=request.agent_run_id,
        )

    def plan(self, request: AgentRequest) -> AgentResponse:
        run_id = request.agent_run_id
        if not request.scope.ip_ranges:
            return AgentResponse(text="Nothing in scope to scan.", agent_run_id=run_id)
        target = request.scope.ip_ranges[0].split("/")[0]
        action = self.suggest or Action(
            tool=ToolName.NMAP, target=target, arguments=["-sV", "--top-ports", "100"]
        )
        self.waiting[run_id] = (request.assessment_id, action)
        return AgentResponse(
            text="Start with a service scan.",
            plan=[
                PlanStep(
                    order=1,
                    title="Find open ports and services",
                    action=action,
                    phase="discovery",
                    reason="Start with what runs before looking for weaknesses.",
                )
            ],
            proposed_action=action,
            risk=RiskLevel.MEDIUM,  # the real harness rates -sV as MEDIUM
            agent_run_id=run_id,
            waiting=True,
        )

    def resume(self, request: AgentRequest) -> AgentResponse:
        resume = request.resume
        run_id = request.agent_run_id
        if resume.agent_run_id != run_id or resume.assessment_id != request.assessment_id:
            raise ApiError(422, "RESUME_RUN_MISMATCH", "The decision is for another run.")
        if run_id not in self.waiting:
            raise ApiError(409, "RUN_NOT_WAITING", "This run is not waiting for a decision.")
        if self.waiting[run_id] != (request.assessment_id, resume.action):
            raise ApiError(422, "RESUME_RUN_MISMATCH", "The decision is for another action.")
        del self.waiting[run_id]
        return AgentResponse(
            text=f"Fake run {resume.decision}.", agent_run_id=run_id, decision=resume.decision
        )


def unsure_analysis(finding: FindingInput) -> FindingAnalysis:
    return FindingAnalysis(
        code=finding.code,
        explanation=finding.title,
        related=[],
        severity_status=finding.severity_status,
        cvss_score=finding.cvss_score,
        evidence="",
        impact="",
        remediation="",
        cwe_ids=finding.cwe_ids,
        owasp_id=finding.owasp_id,
        cve_ids=finding.cve_ids,
        next_step=None,
        unsure="Fake analysis: a person decides.",
    )


class FakeFindingMemory:
    """Stands in for the AI's finding memory (Qdrant): keeps what it was told."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bool]] = []  # (finding code, accepted)
        self.down = False  # set by a test: Qdrant or the embedding model is not running

    async def update(self, finding: FindingOut, accepted: bool) -> None:
        if self.down:
            raise MemoryUnavailable("KNOWLEDGE_UNAVAILABLE")
        self.calls.append((finding.code, accepted))
