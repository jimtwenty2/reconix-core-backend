from pathlib import Path

from reconix_ai.knowledge.items import KnowledgeItem, Source, TextFormat, read_items, write_items


def test_items_survive_a_round_trip(tmp_path: Path) -> None:
    items = [
        KnowledgeItem(Source.CVE, "CVE-2021-44228", "Log4Shell", "Text – with a dash"),
        KnowledgeItem(
            Source.OWASP_TOP10, "A03:2021", "Injection", "# A03", "https://x", TextFormat.MARKDOWN
        ),
    ]
    path = tmp_path / "out" / "items.jsonl"

    write_items(path, items)

    assert read_items(path) == items


def test_text_format_defaults_to_text(tmp_path: Path) -> None:
    path = tmp_path / "old.jsonl"
    path.write_text('{"source": "CWE", "ref_id": "CWE-89", "title": "t", "text": "x"}\n', "utf-8")

    [item] = read_items(path)

    assert item.text_format == TextFormat.TEXT
    assert item.url == ""
