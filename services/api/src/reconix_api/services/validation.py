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
from reconix_api.repositories import tools as tool_repo
from reconix_api.services import findings
from reconix_api.services.tool_runs import VALIDATION_PURPOSE

logger = logging.getLogger(__name__)


# A task nobody references can be garbage-collected before it finishes.
_tasks: set[asyncio.Task] = set()


def start_validation(
    db: Db,
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    action_id: UUID,
    purpose: str,
) -> asyncio.Task | None:
    """After a step finished: if it was a validation step with a COMPLETED tool run, judge
    the findings it is about in this server's own task, with a session of its own. A step
    that is waiting for a person, that failed, or that was a scan starts nothing."""
    if purpose != VALIDATION_PURPOSE:
        return None
    tool_run = tool_repo.latest_completed_run(db, action_id)
    if tool_run is None:
        return None
    task = asyncio.create_task(
        validate_in_background(session_factory, interfaces, mask, operator, tool_run.tool_run_id),
        name=f"VALIDATE {tool_run.tool_run_id}",
    )
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task


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
    except Exception as error:  # the step is finished; a verdict never undoes it
        logger.warning("Validation of tool run %s stopped: %s", tool_run_id, type(error).__name__)
    return verdicts
