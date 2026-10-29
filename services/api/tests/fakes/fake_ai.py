"""Fake of ask_agent: plans one nmap step on the first allowed IP range, then waits.

Like the real agent, it answers a resume with the person's decision and no new step, and
gives the same errors: only PLAN and SUGGEST, only the built-in RECONIX provider, one
decision per waiting run, and a decision only for the action the run waits on.
"""

from uuid import UUID

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    Action,
    AgentRequest,
    AgentResponse,
    AgentTask,
    PlanStep,
    RiskLevel,
    ToolName,
)

SUPPORTED_TASKS = {AgentTask.PLAN, AgentTask.SUGGEST}


class FakeAgent:
    def __init__(self) -> None:
        self.requests: list[AgentRequest] = []
        self.waiting: dict[UUID, tuple[UUID, Action]] = {}  # run -> (assessment, action)

    async def ask_agent(self, request: AgentRequest) -> AgentResponse:
        self.requests.append(request)
        if request.provider != "RECONIX" or request.model is not None:
            raise ApiError(503, "NOT_READY", "Only the built-in RECONIX provider is ready.")
        if request.resume is not None:
            return self.resume(request)
        if request.task not in SUPPORTED_TASKS:
            raise ApiError(422, "TASK_NOT_SUPPORTED", f"The agent cannot do {request.task} yet.")
        if request.agent_run_id in self.waiting:
            raise ApiError(409, "RUN_IS_WAITING", "This run is waiting for a person to decide.")
        return self.plan(request)

    def plan(self, request: AgentRequest) -> AgentResponse:
        run_id = request.agent_run_id
        if not request.scope.ip_ranges:
            return AgentResponse(text="Nothing in scope to scan.", agent_run_id=run_id)
        target = request.scope.ip_ranges[0].split("/")[0]
        action = Action(tool=ToolName.NMAP, target=target, arguments=["-sV", "--top-ports", "100"])
        self.waiting[run_id] = (request.assessment_id, action)
        return AgentResponse(
            text="Start with a service scan.",
            plan=[PlanStep(order=1, title="Find open ports and services", action=action)],
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
