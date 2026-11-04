import os
from pathlib import Path

import pytest

from reconix_ai.knowledge import KnowledgeFilters, Source, search_knowledge, store
from reconix_ai.knowledge.ingest import ingest
from reconix_ai.knowledge.paths import SAMPLE_DATA_DIR
from reconix_ai.knowledge.search import MAX_HIT_CHARS
from reconix_ai.knowledge.store import KnowledgeError


@pytest.fixture
async def loaded(client, embedder, tmp_path: Path):
    guides = tmp_path / "guides"
    guides.mkdir()
    (guides / "nmap.md").write_text(
        "# nmap\n\n## When to use\n"
        "Use nmap first to find open ports and the services behind them.\n"
        "\n## Options\n-sV detects service versions. --top-ports 100 scans the 100 most common.\n",
        encoding="utf-8",
    )
    await ingest(SAMPLE_DATA_DIR, guides_dir=guides, client=client, embed=embedder.embed)
    return client


async def search(client, embedder, query: str, sources: list[Source] | None = None, limit=3):
    filters = KnowledgeFilters(sources=sources or [])
    return await search_knowledge(query, filters, limit=limit, client=client, embed=embedder.embed)


async def test_exact_cve_id_comes_first(loaded, embedder) -> None:
    hits = await search(loaded, embedder, "CVE-2021-44228")

    assert hits[0].ref_id == "CVE-2021-44228"
    assert hits[0].source == Source.CVE
    assert "Log4j" in hits[0].title


async def test_part_of_an_id_still_finds_it(loaded, embedder) -> None:
    hits = await search(loaded, embedder, "44228")

    assert "CVE-2021-44228" in [hit.ref_id for hit in hits]


async def test_cwe_technique_and_owasp_ids(loaded, embedder) -> None:
    assert (await search(loaded, embedder, "CWE-89"))[0].ref_id == "CWE-89"
    assert (await search(loaded, embedder, "t1190"))[0].ref_id == "T1190"
    assert (await search(loaded, embedder, "what is API1:2023"))[0].ref_id == "API1:2023"


async def test_several_ids_all_come_first(loaded, embedder) -> None:
    hits = await search(loaded, embedder, "compare CWE-79 and CWE-89", limit=4)

    assert {hits[0].ref_id, hits[1].ref_id} == {"CWE-79", "CWE-89"}
    assert len({(hit.ref_id, hit.section) for hit in hits}) == len(hits)  # no repeats


async def test_exact_id_respects_the_source_filter(loaded, embedder) -> None:
    hits = await search(loaded, embedder, "CWE-89", sources=[Source.OWASP_TOP10])

    assert all(hit.source == Source.OWASP_TOP10 for hit in hits)


async def test_filter_keeps_only_the_chosen_sources(loaded, embedder) -> None:
    hits = await search(loaded, embedder, "injection", sources=[Source.OWASP_TOP10], limit=5)

    assert hits
    assert {hit.source for hit in hits} == {Source.OWASP_TOP10}
    assert hits[0].ref_id == "A03:2021"


async def test_tool_guides_are_searchable(loaded, embedder) -> None:
    hits = await search(loaded, embedder, "service versions top ports", sources=[Source.TOOL_GUIDE])

    assert hits[0].ref_id == "nmap"
    assert "Options" in hits[0].section or "-sV" in hits[0].text


async def test_query_is_masked_before_it_is_embedded(loaded, embedder) -> None:
    await search(loaded, embedder, "login with password=hunter2 fails")

    assert not any("hunter2" in text for text in embedder.texts)


async def test_empty_query_returns_nothing(loaded, embedder) -> None:
    assert await search(loaded, embedder, "   ") == []


async def test_limit_is_kept_in_bounds(loaded, embedder) -> None:
    assert len(await search(loaded, embedder, "remote code execution", limit=1)) == 1
    assert len(await search(loaded, embedder, "remote code execution", limit=500)) <= 20


async def test_long_hits_are_cut(loaded, embedder) -> None:
    hits = await search(loaded, embedder, "injection", sources=[Source.OWASP_TOP10], limit=5)

    assert all(len(hit.text) <= MAX_HIT_CHARS for hit in hits)


async def test_search_before_any_ingest_gives_a_clear_error(client, embedder) -> None:
    with pytest.raises(KnowledgeError) as raised:
        await search(client, embedder, "CVE-2021-44228")

    assert raised.value.code == "KNOWLEDGE_UNAVAILABLE"
    assert raised.value.__context__ is None


async def test_qdrant_down_gives_a_clear_error(embedder) -> None:
    down = store.connect("http://127.0.0.1:1")  # nothing listens on port 1

    with pytest.raises(KnowledgeError) as raised:
        await search(down, embedder, "sql injection")

    assert raised.value.code == "KNOWLEDGE_UNAVAILABLE"


@pytest.mark.parametrize(
    "url", ["http://10.0.0.5:6333", "https://user:pw@qdrant.example.com", "http://169.254.169.254"]
)
def test_unsafe_qdrant_address_is_refused(url: str) -> None:
    with pytest.raises(KnowledgeError) as raised:
        store.connect(url)

    assert raised.value.code == "KNOWLEDGE_URL_NOT_ALLOWED"
    assert "pw@" not in raised.value.message


def test_compose_qdrant_address_is_allowed() -> None:
    store.connect("http://qdrant:6333")


@pytest.mark.skipif(
    os.environ.get("RECONIX_QDRANT_SMOKE") != "1",
    reason="Set RECONIX_QDRANT_SMOKE=1 with Qdrant and the bge-m3 embedding server running.",
)
async def test_smoke_real_qdrant_and_bge_m3(tmp_path: Path) -> None:
    real = store.connect()
    count = await ingest(SAMPLE_DATA_DIR, guides_dir=tmp_path, client=real)
    hits = await search_knowledge("CVE-2021-44228", client=real)

    assert count > 0
    assert hits[0].ref_id == "CVE-2021-44228"


async def test_ingest_without_any_data_fails_loudly(client, embedder, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        await ingest(tmp_path, guides_dir=tmp_path, client=client, embed=embedder.embed)
