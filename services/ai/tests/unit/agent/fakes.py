"""Fakes for the agent tests: a scripted model, a knowledge search and a request."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

from reconix_ai.agent import AgentDeps
from reconix_ai.knowledge import KnowledgeError, KnowledgeHit, Source
from reconix_ai.providers import Completion, Message, OnPiece, ProviderConfig, ProviderType

NOW = datetime.fromisoformat("2026-10-27T10:00:00+00:00")

UNDERSTOOD = {"goal": "Find open ports on the lab host.", "search": ["nmap service scan"]}
NMAP_STEP = {
    "title": "Find open ports and services",
    "tool": "NMAP",
    "target": "172.20.0.5",
    "arguments": ["-sV", "--top-ports", "100"],
}
PLANNED = {"summary": "Start with a service scan.", "steps": [NMAP_STEP]}
REFLECTED = {"reflection": "Port 22 is open; the services are not yet known.", "search": None}


@dataclass
class Scope:
    """Same fields as the shared ApprovedScope."""

    ip_ranges: list[str] = field(default_factory=lambda: ["172.20.0.0/24"])
    domains: list[str] = field(default_factory=list)
    url_prefixes: list[str] = field(default_factory=lambda: ["http://juice-shop:3000/"])
    repo_paths: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=lambda: ["NMAP", "NUCLEI", "ZAP"])
    max_risk: str = "MEDIUM"
    window_start: datetime | None = None
    window_end: datetime | None = None


@dataclass
class Request:
    """Same fields as the shared AgentRequest."""

    task: str = "PLAN"
    assessment_id: UUID = field(default_factory=uuid4)
    scope: Scope = field(default_factory=Scope)
    provider: str = "RECONIX"
    model: str | None = None
    messages: list[str] = field(default_factory=lambda: ["Scan the lab host for services."])
    tool_results: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    report: object | None = None
    chat_scope: object | None = None
    plan: list[str] = field(default_factory=list)
    recent_reasoning: list[str] = field(default_factory=list)


@dataclass
class ChatScope(Scope):
    """Same fields as the shared ChatScope: a scope and whether it is approved yet."""

    status: str = "DRAFT"


class FakeModel:
    """Gives scripted answers in order and keeps every prompt it was sent."""

    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.prompts: list[list[Message]] = []
        self.streamed = 0  # answers sent through on_piece

    async def complete(
        self,
        messages: list[Message],
        config: ProviderConfig,
        json_answer: bool = False,
        on_piece: OnPiece | None = None,
    ) -> Completion:
        """With on_piece, the answer goes out 7 characters at a time first, as a stream."""
        assert json_answer
        self.prompts.append(messages)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        text = answer if isinstance(answer, str) else json.dumps(answer)
        if on_piece is not None:
            self.streamed += 1
            for start in range(0, len(text), 7):
                await on_piece(text[start : start + 7])
        return Completion(text, config.provider_type, config.model_name, 100, 20, 0)

    def sent_text(self) -> str:
        return "\n".join(m.content for prompt in self.prompts for m in prompt)


class FakeSearch:
    def __init__(self, hits: list[KnowledgeHit] | None = None, down: bool = False) -> None:
        self.hits = hits if hits is not None else [nmap_guide()]
        self.down = down
        self.queries: list[str] = []

    async def search(self, query: str, limit: int = 5) -> list[KnowledgeHit]:
        self.queries.append(query)
        if self.down:
            raise KnowledgeError("KNOWLEDGE_UNAVAILABLE", "Qdrant is down.")
        return self.hits[:limit]


def nmap_guide(text: str = "-sV detects service versions.") -> KnowledgeHit:
    return KnowledgeHit(Source.TOOL_GUIDE, "nmap", "nmap", text, "", "Options", 1.0)


PROVIDER = ProviderConfig(ProviderType.RECONIX, "reconix", api_key="sk-test-key-123456789")


def make_deps(model: FakeModel, search: FakeSearch | None = None) -> AgentDeps:
    return AgentDeps(
        provider=PROVIDER,
        complete=model.complete,
        search=(search or FakeSearch()).search,
        now=lambda: NOW,
    )
