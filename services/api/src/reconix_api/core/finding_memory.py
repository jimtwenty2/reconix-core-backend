"""Accepted findings in the AI Service's memory (reconix_ai.memory), so the AI can answer
questions about them later.

main.py wires the real one below; tests use the fake in tests/fakes/fake_ai.py.
services/findings.py decides what is accepted.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request

from reconix_ai import memory
from reconix_api.schemas.findings import FindingOut

FindingMemory = Callable[[FindingOut, bool], Awaitable[None]]
"""(finding, accepted) -> remember it if accepted, else forget it."""


async def ai_finding_memory(finding: FindingOut, accepted: bool) -> None:
    if not accepted:
        await memory.forget_finding(str(finding.finding_id))
        return
    await memory.remember_finding(
        memory.AcceptedFinding(
            finding_id=str(finding.finding_id),
            assessment_id=str(finding.assessment_id),
            code=finding.code,
            title=finding.title,
            target=finding.target,
            description=finding.description,
            severity_status=str(finding.severity_status),
            finding_status=str(finding.finding_status),
            cwe_ids=list(finding.cwe_ids),
            owasp_id=list(finding.owasp_id),
            cve_ids=list(finding.cve_ids),
            impact=finding.impact,
            remediation=finding.remediation,
        )
    )


def get_finding_memory(request: Request) -> FindingMemory:
    return request.app.state.finding_memory


CurrentFindingMemory = Annotated[FindingMemory, Depends(get_finding_memory)]
