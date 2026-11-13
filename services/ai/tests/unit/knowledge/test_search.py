import os
from pathlib import Path

import pytest

from reconix_ai.knowledge import KnowledgeFilters, KnowledgeHit, Source, search_knowledge, store
from reconix_ai.knowledge.ingest import ingest
from reconix_ai.knowledge.paths import SAMPLE_DATA_DIR
from reconix_ai.knowledge.search import MAX_HIT_CHARS, MAX_SECTIONS_PER_REF, cap_sections, spread
from reconix_ai.knowledge.store import KnowledgeError


def test_spread_takes_turns_by_source() -> None:
    """B2: by score alone two long passages of one source push the short CWE entry out
    of the top 3. One hit per source each round brings it back; inside a source the
    score order stays."""
    hits = [
        hit_of("A03:2021", "/1/"),
        hit_of("A03:2021", "/2/"),
        hit_of("CVE-2023-34362", "/", Source.CVE),
        hit_of("CWE-89", "/", Source.CWE),
    ]

    ordered = [hit.ref_id for hit in spread(hits)]

    assert ordered[:3] == ["A03:2021", "CVE-2023-34362", "CWE-89"]


def test_spread_keeps_one_source_as_it_is() -> None:
    hits = [hit_of("CVE-1", "/", Source.CVE), hit_of("CVE-2", "/", Source.CVE)]

    assert [hit.ref_id for hit in spread(hits)] == ["CVE-1", "CVE-2"]


def hit_of(ref_id: str, section: str, source: Source = Source.OWASP_TOP10) -> KnowledgeHit:
    return KnowledgeHit(
        source=source,
        ref_id=ref_id,
        title=ref_id,
        text="text",
        url="",
        section=section,
        score=0.5,
    )


def test_one_document_cannot_flood_the_list() -> None:
    found = [hit_of("A03:2021", f"/s{i}/") for i in range(5)] + [hit_of("CWE-89", "/")]

    kept = cap_sections(found, set())

    assert [h.ref_id for h in kept] == ["A03:2021", "A03:2021", "CWE-89"]


def test_cap_sections_skips_the_exact_hits() -> None:
    exact = hit_of("CWE-89", "/")
    found = [exact, hit_of("CWE-89", "/2/")]

    kept = cap_sections(found, {(exact.ref_id, exact.section)})

    assert kept == [found[1]]


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


async def test_search_caps_sections_of_one_document(client, embedder, tmp_path: Path) -> None:
    guides = tmp_path / "guides"
    guides.mkdir()
    sections = "\n\n".join(
        f"## Part {i}\nThe zebrafish topic appears in part {i} with enough words to pass "
        "the minimum piece length."
        for i in range(6)
    )
    (guides / "zebrafish.md").write_text(f"# Zebrafish\n\n{sections}\n", encoding="utf-8")
    await ingest(SAMPLE_DATA_DIR, guides_dir=guides, client=client, embed=embedder.embed)

    hits = await search(client, embedder, "zebrafish", limit=10)

    assert 0 < sum(h.ref_id == "zebrafish" for h in hits) <= MAX_SECTIONS_PER_REF


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
