"""The verdict for a finished validation step, run after the step's request has answered.

A step a plan sends with `purpose == "validation"` is a proof of concept: the existing finding
it hits waits for a verdict. Judging one finding is one model call (seconds), so it never runs
inside the request that finished the tool run, the way a person's finding review is already
put after its answer. The step is COMPLETED before this starts, so a model that is down, or
slow, or answers nonsense costs the finding its verdict and nothing else.
"""

import asyncio
import logging
from uuid import UUID

from sqlalchemy.orm import Session as Db
from sqlalchemy.orm import sessionmaker

from reconix_api.core.interfaces import Interfaces, Operator
from reconix_api.core.masking import MaskSecrets
from reconix_api.models.enums import AgentRunStatus
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import tools as tool_repo
from reconix_api.services import findings
from reconix_api.services.tool_runs import VALIDATION_PURPOSE

logger = logging.getLogger(__name__)


def start_validations(
    db: Db,
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    agent_run_id: UUID | None,
) -> asyncio.Task | None:
    """After a step is sent: if the plan run's step just finished as a validation, judge the
    findings it hit in this server's own task, with a session of its own. A step that is
    waiting for a person, that failed, or that was a scan starts nothing."""
    if agent_run_id is None:
        return None
    plan = agent_run_repo.get(db, agent_run_id)
    if plan is None or plan.agent_runs_status != AgentRunStatus.WAITING_APPROVAL:
        return None
    finished = tool_repo.latest_finished(db, agent_run_id)
    if finished is None:
        return None
    tool_run, action = finished
    if action.purpose != VALIDATION_PURPOSE:
        return None
    return asyncio.create_task(
        validate_in_background(session_factory, interfaces, mask, operator, tool_run.tool_run_id),
        name=f"VALIDATE {tool_run.tool_run_id}",
    )


async def validate_in_background(
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    tool_run_id: UUID,
) -> list[str]:
    """The verdicts this run gave, one per finding it validated (empty when it is not a
    COMPLETED validation step). Anything that goes wrong is logged by its type, never raised:
    nothing waits for this task and the step is already COMPLETED."""
    verdicts: list[str] = []
    try:
        with session_factory() as db:
            step = tool_repo.completed_step(db, tool_run_id)
            if step is None or step[1].purpose != VALIDATION_PURPOSE:
                return verdicts
            results = await findings.run_validation(db, interfaces, mask, operator, step[0])
            verdicts = [result.validation_status.value for result in results]
    except Exception as error:  # noqa: BLE001 - the step is finished; a verdict never undoes it
        logger.warning("Validation of tool run %s stopped: %s", tool_run_id, type(error).__name__)
    return verdicts
