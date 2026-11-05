"""Re-ingest the knowledge, as one background job.

- scope NEW: the add-ons waiting (uploaded with ingest_now=false) are put into the knowledge
  search, then forgotten from the waiting store. Quick: nothing else is touched.
- scope ALL: the public knowledge (CVE, CWE, OWASP, ATT&CK, tool guides) is loaded again,
  every ingested add-on's passages are embedded again, and the waiting ones are put in.

One job at a time (409 REINGEST_RUNNING); it runs in this process, so an API restart ends
it (a waiting add-on stays waiting, nothing is lost). Uploads wait for the add-on step (the
store's upload lock). Audit: started, one line per add-on put in, and finished.
"""

import asyncio
from datetime import UTC, datetime

from reconix_api.core import knowledge_add_ons, knowledge_pending
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.knowledge_add_ons import KnowledgeStore, ReingestJob
from reconix_api.schemas.knowledge_add_ons import KnowledgeReingestOut
from reconix_api.services.audit import audit

_jobs: set[asyncio.Task] = set()  # kept alive while they run


def status(store: KnowledgeStore) -> KnowledgeReingestOut:
    job = store.reingest
    return KnowledgeReingestOut(
        status=job.status,
        scope=job.scope,
        step=job.step,
        public_pieces=job.public_pieces,
        add_ons_done=job.add_ons_done,
        add_ons_total=job.add_ons_total,
        new_ingested=job.new_ingested,
        started_at=job.started_at,
        finished_at=job.finished_at,
        error_code=job.error_code,
        error_message=job.error_message,
    )


def start(
    store: KnowledgeStore,
    settings: Settings,
    write_audit: WriteAudit,
    operator: Operator,
    scope: str = "ALL",
) -> KnowledgeReingestOut:
    """Start the job and answer at once; GET /knowledge/reingest follows it."""
    job = store.reingest
    if job.status == "RUNNING":
        raise ApiError(409, "REINGEST_RUNNING", "The knowledge is being re-ingested already.")
    step = "PUBLIC" if scope == "ALL" else "ADD_ONS"
    _copy(ReingestJob(status="RUNNING", scope=scope, step=step, started_at=_now()), job)
    audit(write_audit, "KNOWLEDGE_REINGEST_STARTED", operator, details={"scope": scope})
    task = asyncio.ensure_future(_run(store, settings, write_audit, operator))
    job.task = task
    _jobs.add(task)
    task.add_done_callback(_jobs.discard)
    return status(store)


async def _run(
    store: KnowledgeStore, settings: Settings, write_audit: WriteAudit, operator: Operator
) -> None:
    job = store.reingest
    try:
        if job.scope == "ALL":
            job.public_pieces = await knowledge_add_ons.ingest_public(store)
            job.step = "ADD_ONS"
        async with store.adding:
            ingested = await knowledge_add_ons.list_all(store) if job.scope == "ALL" else []
            waiting = knowledge_pending.list_all(settings)
            job.add_ons_total = len(ingested) + len(waiting)
            for add_on in ingested:
                await knowledge_add_ons.reindex(store, add_on)
                job.add_ons_done += 1
            for add_on in waiting:
                await _put_in(store, settings, write_audit, operator, add_on.knowledge_add_on_id)
                job.add_ons_done += 1
                job.new_ingested += 1
        job.status = "COMPLETED"
    except ApiError as error:
        job.status, job.error_code, job.error_message = "FAILED", error.code, error.message
    except Exception:  # the job must end with a status, never hang RUNNING
        job.status, job.error_code = "FAILED", "REINGEST_FAILED"
        job.error_message = "The knowledge could not be re-ingested."
    job.finished_at = _now()
    details = {
        "status": job.status,
        "scope": job.scope,
        "public_pieces": job.public_pieces,
        "add_ons": job.add_ons_done,
        "new_ingested": job.new_ingested,
        "code": job.error_code,
    }
    audit(write_audit, "KNOWLEDGE_REINGEST_FINISHED", operator, details=details)


async def _put_in(
    store: KnowledgeStore,
    settings: Settings,
    write_audit: WriteAudit,
    operator: Operator,
    knowledge_add_on_id: str,
) -> None:
    """One waiting add-on into the knowledge search; forgotten from the waiting store only
    once it is saved (a failure leaves it waiting, never lost)."""
    waiting = knowledge_pending.load(settings, knowledge_add_on_id)
    if waiting is None:
        return  # removed meanwhile
    add_on, passages = waiting
    await knowledge_add_ons.save(store, add_on, passages)
    knowledge_pending.remove(settings, knowledge_add_on_id)
    details = {"knowledge_add_on_id": add_on.knowledge_add_on_id, "name": add_on.name}
    audit(write_audit, "KNOWLEDGE_ADD_ON_INGESTED", operator, details=details)


def _copy(source: ReingestJob, target: ReingestJob) -> None:
    for name in ReingestJob.__dataclass_fields__:
        if name != "task":
            setattr(target, name, getattr(source, name))


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
