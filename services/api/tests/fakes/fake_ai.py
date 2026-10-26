"""Fake of ask_agent: always plans one nmap step on the first allowed IP range."""

from reconix_api.core.interfaces import (
    Action,
    AgentRequest,
    AgentResponse,
    AgentTask,
    PlanStep,
    ToolName,
)


class FakeAgent:
    def __init__(self) -> None:
        self.requests: list[AgentRequest] = []

    async def ask_agent(self, request: AgentRequest) -> AgentResponse:
        self.requests.append(request)
        if request.task in (AgentTask.PLAN, AgentTask.SUGGEST) and request.scope.ip_ranges:
            target = request.scope.ip_ranges[0].split("/")[0]
            action = Action(
                tool=ToolName.NMAP, target=target, arguments=["-sV", "--top-ports", "100"]
            )
            return AgentResponse(
                text="Start with a service scan.",
                plan=[PlanStep(order=1, title="Find open ports and services", action=action)],
                proposed_action=action,
            )
        return AgentResponse(text=f"Fake {request.task} answer.")
