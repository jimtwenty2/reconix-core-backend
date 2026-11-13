from pathlib import Path

import pytest

from reconix_ai.knowledge import KnowledgeFilters, Source, search_knowledge, store
from reconix_ai.knowledge.add_ons import (
    MAX_CHARS,
    MAX_PASSAGES,
    AddOn,
    add_on_passages,
    list_add_ons,
    remove_add_on,
    remove_all_add_ons,
    save_add_on,
    split_passages,
)
from reconix_ai.knowledge.ingest import ingest
from reconix_ai.knowledge.items import KnowledgeItem, write_items
from reconix_ai.knowledge.paths import SAMPLE_DATA_DIR
from reconix_ai.knowledge.store import KnowledgeError

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documented fake key, joined at run time
RUNBOOK = (
    "Rotate the staging database credentials every Friday.\n\n"
    "The payments service listens on port 8443 behind the internal gateway."
)


def add_on(knowledge_add_on_id: str = "4f6b7a52-0c55-4a8e-9f0e-3b8d7c1a2e90", **changes) -> AddOn:
    fields = {
        "knowledge_add_on_id": knowledge_add_on_id,
        "name": "runbook.md",
        "kind": "MD",
        "size_bytes": len(RUNBOOK),
        "chunk_count": 1,
        "interface": "cli",
        "created_at": "2026-10-30T09:00:00+00:00",
    }
    return AddOn(**(fields | changes))


async def search(client, embedder, query: str, sources: list[Source] | None = None):
    filters = KnowledgeFilters(sources=sources or [])
    return await search_knowledge(query, filters, client=client, embed=embedder.embed)


async def test_a_saved_add_on_is_listed(client, embedder) -> None:
    await save_add_on(add_on(), [RUNBOOK], client=client, embed=embedder.embed)

    assert await list_add_ons(client) == [add_on()]


async def test_a_saved_add_on_is_searchable(client, embedder) -> None:
    await save_add_on(add_on(), [RUNBOOK], client=client, embed=embedder.embed)

    hits = await search(client, embedder, "payments service port", [Source.USER_DOC])

    assert hits[0].source == Source.USER_DOC
    assert hits[0].title == "runbook.md"
    assert "8443" in hits[0].text


async def test_secrets_are_masked_before_they_are_saved(client, embedder) -> None:
    secret = f"aws key {AWS_KEY} for the backups"
    named = add_on(name=f"{AWS_KEY}.md")

    await save_add_on(named, [secret], client=client, embed=embedder.embed)

    records, _ = await client.scroll(store.COLLECTION, with_payload=True)
    assert AWS_KEY not in str(records)
    assert AWS_KEY not in " ".join(embedder.texts)
    assert AWS_KEY not in (await list_add_ons(client))[0].name


async def test_list_is_oldest_first(client, embedder) -> None:
    newer = add_on("b0000000-0000-4000-8000-000000000002", created_at="2026-10-30T10:00:00+00:00")
    older = add_on("a0000000-0000-4000-8000-000000000001", created_at="2026-10-30T08:00:00+00:00")
    for item in (newer, older):
        await save_add_on(item, [RUNBOOK], client=client, embed=embedder.embed)

    assert [item.knowledge_add_on_id for item in await list_add_ons(client)] == [
        older.knowledge_add_on_id,
        newer.knowledge_add_on_id,
    ]


async def test_list_before_anything_is_saved_is_empty(client) -> None:
    assert await list_add_ons(client) == []


async def test_remove_takes_every_piece_of_one_add_on(client, embedder) -> None:
    keep = add_on("a0000000-0000-4000-8000-000000000001")
    drop = add_on("b0000000-0000-4000-8000-000000000002", chunk_count=2)
    await save_add_on(keep, [RUNBOOK], client=client, embed=embedder.embed)
    await save_add_on(drop, ["first piece of text", "second"], client=client, embed=embedder.embed)

    await remove_add_on(drop.knowledge_add_on_id, client)

    assert await list_add_ons(client) == [keep]
    records, _ = await client.scroll(store.COLLECTION, with_payload=True)
    assert {record.payload["ref_id"] for record in records} == {keep.knowledge_add_on_id}


async def test_remove_all_keeps_the_public_knowledge(client, embedder, tmp_path: Path) -> None:
    await ingest(SAMPLE_DATA_DIR, guides_dir=tmp_path, client=client, embed=embedder.embed)
    await save_add_on(add_on(), [RUNBOOK], client=client, embed=embedder.embed)

    await remove_all_add_ons(client)

    assert await list_add_ons(client) == []
    assert (await search(client, embedder, "CVE-2021-44228"))[0].ref_id == "CVE-2021-44228"


async def test_a_new_ingest_keeps_the_add_ons(client, embedder, tmp_path: Path) -> None:
    await ingest(SAMPLE_DATA_DIR, guides_dir=tmp_path, client=client, embed=embedder.embed)
    await save_add_on(add_on(), [RUNBOOK], client=client, embed=embedder.embed)

    await ingest(SAMPLE_DATA_DIR, guides_dir=tmp_path, client=client, embed=embedder.embed)

    assert await list_add_ons(client) == [add_on()]
    assert (await search(client, embedder, "CVE-2021-44228"))[0].ref_id == "CVE-2021-44228"


async def test_a_rebuild_drops_the_add_ons_too(client, embedder, tmp_path: Path) -> None:
    await save_add_on(add_on(), [RUNBOOK], client=client, embed=embedder.embed)

    await ingest(
        SAMPLE_DATA_DIR, guides_dir=tmp_path, client=client, embed=embedder.embed, rebuild=True
    )

    assert await list_add_ons(client) == []


async def test_the_ingest_refuses_add_on_items(client, embedder, tmp_path: Path) -> None:
    item = KnowledgeItem(source=Source.USER_DOC, ref_id="x", title="x", text="planted")
    write_items(tmp_path / "planted.jsonl", [item])

    with pytest.raises(ValueError):
        await ingest(tmp_path, guides_dir=tmp_path, client=client, embed=embedder.embed)


async def test_every_passage_of_an_add_on_can_be_found(client, embedder) -> None:
    passages = ["zebra gateway listens on 9443", "zebra gateway logs go to the SIEM"]
    await save_add_on(add_on(chunk_count=2), passages, client=client, embed=embedder.embed)

    hits = await search(client, embedder, "zebra gateway", [Source.USER_DOC])

    assert len(hits) == 2
    assert {hit.section for hit in hits} == {"/Part 1/", "/Part 2/"}


async def test_an_add_on_with_no_passages_is_refused(client, embedder) -> None:
    with pytest.raises(ValueError):
        await save_add_on(add_on(), [], client=client, embed=embedder.embed)


async def test_qdrant_down_gives_a_clear_error(embedder) -> None:
    down = store.connect("http://127.0.0.1:1")  # nothing listens on port 1

    with pytest.raises(KnowledgeError) as raised:
        await save_add_on(add_on(), [RUNBOOK], client=down, embed=embedder.embed)

    assert raised.value.code == "KNOWLEDGE_UNAVAILABLE"
    with pytest.raises(KnowledgeError):
        await list_add_ons(down)


def test_short_text_is_one_passage() -> None:
    assert split_passages(RUNBOOK) == ([RUNBOOK], False)


def test_paragraphs_are_joined_up_to_the_limit() -> None:
    text = "\n\n".join(f"Paragraph {n} " + "word " * 40 for n in range(30))

    passages, cut = split_passages(text)

    assert not cut
    assert len(passages) > 1
    assert all(len(passage) <= MAX_CHARS for passage in passages)
    assert passages[0].startswith("Paragraph 0")


def test_a_long_paragraph_is_cut_in_windows() -> None:
    passages, _ = split_passages("word " * 2000)

    assert len(passages) > 1
    assert all(len(passage) <= MAX_CHARS for passage in passages)


def test_text_past_the_passage_limit_is_cut() -> None:
    passages, cut = split_passages("\n\n".join("x" * MAX_CHARS for _ in range(MAX_PASSAGES + 5)))

    assert cut
    assert len(passages) == MAX_PASSAGES


def test_blank_text_has_no_passages() -> None:
    assert split_passages(" \n\n \n") == ([], False)


async def test_an_add_on_gives_back_its_passages_in_order(client, embedder) -> None:
    passages = [f"Passage {i}: CWE-89 in the search form." for i in range(300)]  # past one page
    await save_add_on(add_on(chunk_count=300), passages, client=client, embed=embedder.embed)
    other = add_on("9c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f", name="other.md")
    await save_add_on(other, ["Another document."], client=client, embed=embedder.embed)

    assert await add_on_passages(add_on().knowledge_add_on_id, client) == passages
    assert await add_on_passages("00000000-0000-4000-8000-000000000000", client) == []


async def test_passages_come_back_masked(client, embedder) -> None:
    await save_add_on(add_on(), [f"key {AWS_KEY} here"], client=client, embed=embedder.embed)

    [text] = await add_on_passages(add_on().knowledge_add_on_id, client)
    assert AWS_KEY not in text
