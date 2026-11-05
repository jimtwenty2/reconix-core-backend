"""Re-ingesting the knowledge: the public knowledge again, then every add-on's passages,
as one background job, against Qdrant in this process and a fake embedder."""

import asyncio
from uuid import uuid4

import pytest

from reconix_ai.knowledge import AddOn, Source, save_add_on, search_knowledge, store
from reconix_ai.knowledge.search import KnowledgeFilters
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator
from reconix_api.core.knowledge_add_ons import KnowledgeStore
from reconix_api.services import knowledge_reingest
from tests.fakes.fake_core import FakeAudit
from tests.unit.api.test_knowledge_add_ons import fake_embed

OPERATOR = Operator(session_id=uuid4(), actor="tester@host")
SETTINGS = Settings(knowledge_pending_dir="/nonexistent-reconix-pending")  # nothing waits


def add_on(name: str) -> AddOn:
    return AddOn(
        knowledge_add_on_id=str(uuid4()),
        name=name,
        kind="MD",
        size_bytes=10,
        chunk_count=1,
        interface="web",
        created_at="2026-11-05T10:00:00+00:00",
    )


async def test_the_job_loads_the_public_knowledge_and_reindexes_every_add_on():
    qdrant = store.connect(":memory:")
    knowledge = KnowledgeStore(client=qdrant, embed=fake_embed)
    runbook = add_on("runbook.md")
    await save_add_on(runbook, ["Rotate the payment keys."], qdrant, fake_embed)
    audit = FakeAudit()

    started = knowledge_reingest.start(knowledge, SETTINGS, audit.write_audit, OPERATOR)
    assert (started.status, started.step) == ("RUNNING", "PUBLIC")
    with pytest.raises(ApiError) as twice:
        knowledge_reingest.start(knowledge, SETTINGS, audit.write_audit, OPERATOR)
    assert twice.value.code == "REINGEST_RUNNING"

    await knowledge.reingest.task
    done = knowledge_reingest.status(knowledge)
    assert done.status == "COMPLETED"
    assert done.step == "ADD_ONS"
    assert done.public_pieces > 0
    assert (done.add_ons_done, done.add_ons_total) == (1, 1)
    assert done.finished_at is not None
    # the public knowledge and the add-on are both searchable
    hits = await search_knowledge(
        "payment keys", KnowledgeFilters(sources=[Source.USER_DOC]), client=qdrant, embed=fake_embed
    )
    assert hits and hits[0].ref_id == runbook.knowledge_add_on_id
    assert [e.event_type for e in audit.events] == [
        "KNOWLEDGE_REINGEST_STARTED",
        "KNOWLEDGE_REINGEST_REFUSED",  # the second start: one line for that decision too
        "KNOWLEDGE_REINGEST_FINISHED",
    ]


async def test_a_failure_ends_the_job_failed_with_why():
    async def model_down(texts):
        from reconix_ai.providers import ProviderError

        raise ProviderError("MODEL_UNAVAILABLE", "The embedding model is not running.")

    knowledge = KnowledgeStore(client=store.connect(":memory:"), embed=model_down)
    audit = FakeAudit()
    knowledge_reingest.start(knowledge, SETTINGS, audit.write_audit, OPERATOR)
    await knowledge.reingest.task

    failed = knowledge_reingest.status(knowledge)
    assert failed.status == "FAILED"
    assert failed.error_code == "MODEL_UNAVAILABLE"
    assert failed.step == "PUBLIC"
    assert audit.events[-1].details["status"] == "FAILED"
    # it can be started again
    knowledge_reingest.start(knowledge, SETTINGS, audit.write_audit, OPERATOR)
    await asyncio.wait_for(knowledge.reingest.task, 30)


def test_before_any_job_the_status_is_idle():
    knowledge = KnowledgeStore(client=store.connect(":memory:"), embed=fake_embed)
    assert knowledge_reingest.status(knowledge).status == "IDLE"


async def test_scope_new_puts_only_the_waiting_add_ons_in(tmp_path):
    from cryptography.fernet import Fernet

    from reconix_api.core import knowledge_pending

    settings = Settings(
        provider_encryption_key=Fernet.generate_key().decode(),
        knowledge_pending_dir=str(tmp_path / "pending"),
    )
    qdrant = store.connect(":memory:")
    knowledge = KnowledgeStore(client=qdrant, embed=fake_embed)
    waiting = add_on("waiting.md")
    knowledge_pending.save(settings, waiting, ["Rotate the vault keys every Friday."])
    audit = FakeAudit()

    started = knowledge_reingest.start(knowledge, settings, audit.write_audit, OPERATOR, "NEW")
    assert (started.scope, started.step) == ("NEW", "ADD_ONS")  # no public step
    await knowledge.reingest.task

    done = knowledge_reingest.status(knowledge)
    assert (done.status, done.public_pieces, done.new_ingested) == ("COMPLETED", 0, 1)
    assert knowledge_pending.list_all(settings) == []  # no longer waiting
    filters = KnowledgeFilters(sources=[Source.USER_DOC])
    hits = await search_knowledge("vault keys", filters, client=qdrant, embed=fake_embed)
    assert hits and hits[0].ref_id == waiting.knowledge_add_on_id
    assert "KNOWLEDGE_ADD_ON_INGESTED" in [e.event_type for e in audit.events]


def pending_settings(tmp_path) -> Settings:
    from cryptography.fernet import Fernet

    return Settings(
        provider_encryption_key=Fernet.generate_key().decode(),
        knowledge_pending_dir=str(tmp_path / "pending"),
    )


def slow_embed():
    """A fake embedder that waits for `go` once the add-on step embeds, so a test can act
    while the job is saving."""
    go = asyncio.Event()
    saving = asyncio.Event()

    async def embed(texts):
        if any("quokka" in t for t in texts):  # only the test's own add-ons say it
            saving.set()
            await go.wait()
        return await fake_embed(texts)

    return embed, go, saving


async def searchable(qdrant, query: str) -> bool:
    filters = KnowledgeFilters(sources=[Source.USER_DOC])
    return bool(await search_knowledge(query, filters, client=qdrant, embed=fake_embed))


async def test_a_waiting_add_on_removed_while_it_is_put_in_stays_removed(tmp_path):
    from reconix_api.core import knowledge_pending
    from reconix_api.services import knowledge_add_ons

    settings = pending_settings(tmp_path)
    qdrant = store.connect(":memory:")
    embed, go, saving = slow_embed()
    knowledge = KnowledgeStore(client=qdrant, embed=embed)
    waiting = add_on("waiting.md")
    knowledge_pending.save(settings, waiting, ["Rotate the quokka vault keys every Friday."])
    audit = FakeAudit()

    knowledge_reingest.start(knowledge, settings, audit.write_audit, OPERATOR, "NEW")
    await asyncio.wait_for(saving.wait(), 10)
    from uuid import UUID

    await knowledge_add_ons.remove(
        knowledge, settings, audit.write_audit, OPERATOR, UUID(waiting.knowledge_add_on_id)
    )
    go.set()
    await knowledge.reingest.task

    assert not await searchable(qdrant, "quokka vault keys")
    assert knowledge_pending.list_all(settings) == []
    assert knowledge_reingest.status(knowledge).new_ingested == 0
    events = [e.event_type for e in audit.events]
    assert "KNOWLEDGE_ADD_ON_INGESTED" not in events
    assert events.count("KNOWLEDGE_ADD_ON_REMOVED") == 1


async def test_an_add_on_removed_while_it_is_re_embedded_stays_removed(tmp_path):
    from uuid import UUID

    from reconix_api.services import knowledge_add_ons

    settings = pending_settings(tmp_path)
    qdrant = store.connect(":memory:")
    runbook = add_on("runbook.md")
    await save_add_on(runbook, ["Rotate the quokka payment keys."], qdrant, fake_embed)
    embed, go, saving = slow_embed()
    knowledge = KnowledgeStore(client=qdrant, embed=embed)
    audit = FakeAudit()

    knowledge_reingest.start(knowledge, settings, audit.write_audit, OPERATOR)
    await asyncio.wait_for(saving.wait(), 60)
    await knowledge_add_ons.remove(
        knowledge, settings, audit.write_audit, OPERATOR, UUID(runbook.knowledge_add_on_id)
    )
    go.set()
    await knowledge.reingest.task

    assert knowledge_reingest.status(knowledge).status == "COMPLETED"
    assert not await searchable(qdrant, "quokka payment keys")


async def test_a_failed_re_embed_keeps_the_passages_waiting(tmp_path):
    from reconix_api.core import knowledge_pending

    settings = pending_settings(tmp_path)
    qdrant = store.connect(":memory:")
    runbook = add_on("runbook.md")
    await save_add_on(runbook, ["Rotate the zebrafinch keys."], qdrant, fake_embed)

    async def down_for_add_ons(texts):
        if any("zebrafinch" in t for t in texts):
            from reconix_ai.providers import ProviderError

            raise ProviderError("MODEL_UNAVAILABLE", "The embedding model is not running.")
        return await fake_embed(texts)

    knowledge = KnowledgeStore(client=qdrant, embed=down_for_add_ons)
    knowledge_reingest.start(knowledge, settings, FakeAudit().write_audit, OPERATOR)
    await knowledge.reingest.task

    assert knowledge_reingest.status(knowledge).status == "FAILED"
    kept = knowledge_pending.load(settings, runbook.knowledge_add_on_id)
    assert kept is not None and kept[1] == ["Rotate the zebrafinch keys."]


async def test_a_cancelled_job_ends_failed_interrupted_with_one_closing_line(tmp_path):
    embed, _go, saving = slow_embed()
    qdrant = store.connect(":memory:")
    await save_add_on(add_on("runbook.md"), ["Rotate the quokka payment keys."], qdrant, fake_embed)
    knowledge = KnowledgeStore(client=qdrant, embed=embed)
    audit = FakeAudit()

    knowledge_reingest.start(knowledge, pending_settings(tmp_path), audit.write_audit, OPERATOR)
    await asyncio.wait_for(saving.wait(), 60)
    knowledge.reingest.task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await knowledge.reingest.task

    job = knowledge_reingest.status(knowledge)
    assert (job.status, job.error_code) == ("FAILED", "INTERRUPTED")
    finished = [e for e in audit.events if e.event_type == "KNOWLEDGE_REINGEST_FINISHED"]
    assert len(finished) == 1 and finished[0].details["code"] == "INTERRUPTED"


async def test_an_unreadable_waiting_file_can_still_be_removed(tmp_path):
    from uuid import UUID

    from cryptography.fernet import Fernet

    from reconix_api.core import knowledge_pending
    from reconix_api.services import knowledge_add_ons

    settings = pending_settings(tmp_path)
    waiting = add_on("waiting.md")
    knowledge_pending.save(settings, waiting, ["Rotate the vault keys."])
    other_key = Settings(
        provider_encryption_key=Fernet.generate_key().decode(),
        knowledge_pending_dir=settings.knowledge_pending_dir,
    )
    knowledge = KnowledgeStore(client=store.connect(":memory:"), embed=fake_embed)
    audit = FakeAudit()

    await knowledge_add_ons.remove(
        knowledge, other_key, audit.write_audit, OPERATOR, UUID(waiting.knowledge_add_on_id)
    )

    assert knowledge_pending.load(settings, waiting.knowledge_add_on_id) is None
    assert [e.event_type for e in audit.events] == ["KNOWLEDGE_ADD_ON_REMOVED"]
