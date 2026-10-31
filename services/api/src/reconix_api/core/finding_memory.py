"""Accepted findings in the AI Service's memory (reconix_ai.memory), so the AI can answer
questions about them later.

main.py wires the real one below; tests use the fake in tests/fakes/fake_ai.py.
services/findings.py decides what is accepted.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request

from reconix_ai import memory
from reconix_ai.knowledge import KnowledgeError
from reconix_ai.providers import ProviderError
from reconix_api.schemas.findings import FindingOut

FindingMemory = Callable[[FindingOut, bool], Awaitable[None]]
"""(finding, accepted) -> remember it if accepted, else forget it."""


class MemoryUnavailable(Exception):
    """Qdrant or the embedding model is down. code is UPPERCASE; the message is never kept,
    because a connection error can carry an address."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


async def ai_finding_memory(finding: FindingOut, accepted: bool) -> None:
    failure = None
    try:
        if accepted:
            await memory.remember_finding(accepted_finding(finding))
        else:
            await memory.forget_finding(str(finding.finding_id))
    except (KnowledgeError, ProviderError) as error:
        failure = MemoryUnavailable(error.code)
    if failure is not None:
        raise failure  # outside the except block, so the original error is not attached


def accepted_finding(finding: FindingOut) -> memory.AcceptedFinding:
    return memory.AcceptedFinding(
        finding_id=str(finding.finding_id),
        assessment_id=str(finding.assessment_id),
        code=finding.code,
        title=finding.title,
        target=finding.target,
        description=finding.description,
        severity_status=finding.severity_status.value,
        finding_status=finding.finding_status.value,
        cwe_ids=list(finding.cwe_ids),
        owasp_id=list(finding.owasp_id),
        cve_ids=list(finding.cve_ids),
        impact=finding.impact,
        remediation=finding.remediation,
    )


def get_finding_memory(request: Request) -> FindingMemory:
    return request.app.state.finding_memory


CurrentFindingMemory = Annotated[FindingMemory, Depends(get_finding_memory)]
