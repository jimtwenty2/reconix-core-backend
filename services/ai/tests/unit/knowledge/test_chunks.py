from pathlib import Path

from reconix_ai.knowledge.chunks import load_items, make_chunks
from reconix_ai.knowledge.items import KnowledgeItem, Source, TextFormat
from reconix_ai.knowledge.paths import SAMPLE_DATA_DIR

GUIDE = """# A03:2021 Injection

## Description
An application is vulnerable when user data is not validated, filtered or sanitized.

## How to Prevent
Use a safe API which avoids using the interpreter entirely, or parameterized queries.

## Empty
"""


def test_a_cve_stays_one_piece() -> None:
    item = KnowledgeItem(Source.CVE, "CVE-2021-44228", "Log4Shell", "A long CVE text. " * 50)

    [chunk] = make_chunks([item])

    assert chunk.ref_id == "CVE-2021-44228"
    assert chunk.index == 0


def test_markdown_is_cut_at_headings_and_empty_pieces_dropped() -> None:
    item = KnowledgeItem(
        Source.OWASP_TOP10, "A03:2021", "Injection", GUIDE, text_format=TextFormat.MARKDOWN
    )

    chunks = make_chunks([item])

    assert [c.text.splitlines()[0] for c in chunks] == ["## Description", "## How to Prevent"]
    assert [c.index for c in chunks] == [0, 1]
    assert all("A03:2021 Injection" in c.section for c in chunks)


def test_secrets_are_masked_before_saving() -> None:
    item = KnowledgeItem(Source.TOOL_GUIDE, "zap", "zap", "Run with api_key=abc123secret to start.")

    [chunk] = make_chunks([item])

    assert "abc123secret" not in chunk.text
    assert "[MASKED:api_key]" in chunk.text


def test_secrets_in_headings_links_and_names_are_masked_too() -> None:
    guide = (
        "# Start with api_key=abc123secretvalue\n\n"
        "## Usage\nRun the scan against the lab target and read the JSON result file.\n"
    )
    item = KnowledgeItem(
        Source.TOOL_GUIDE,
        "zap-token=zzsecret99",
        "zap",
        guide,
        url="https://user:hunter2@example.com/zap",
        text_format=TextFormat.MARKDOWN,
    )

    chunks = make_chunks([item])

    assert chunks
    for chunk in chunks:
        saved = " ".join([chunk.ref_id, chunk.title, chunk.text, chunk.url, chunk.section])
        assert "abc123secretvalue" not in saved
        assert "zzsecret99" not in saved
        assert "hunter2" not in saved


def test_load_items_reads_every_file_and_the_guides(tmp_path: Path) -> None:
    (tmp_path / "gitleaks.md").write_text("# gitleaks\nFinds secrets in git history.", "utf-8")

    items = load_items(SAMPLE_DATA_DIR, tmp_path)

    sources = {item.source for item in items}
    assert sources == {
        Source.CVE,
        Source.CWE,
        Source.ATTACK,
        Source.OWASP_TOP10,
        Source.OWASP_API_TOP10,
        Source.TOOL_GUIDE,
    }
    assert any(item.ref_id == "gitleaks" for item in items)
