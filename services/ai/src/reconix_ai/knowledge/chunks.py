"""Items -> pieces ready to search, with LlamaIndex.

Each CVE, CWE and ATT&CK technique stays one piece. OWASP pages and tool
guides are cut at their headings. Secrets are masked before anything leaves
this file.
"""

from dataclasses import dataclass
from pathlib import Path

from llama_index.core import Document
from llama_index.core.node_parser import MarkdownNodeParser

from reconix_ai.harness import mask_secrets
from reconix_ai.knowledge.items import KnowledgeItem, Source, TextFormat, read_items

# Pieces shorter than this (a heading with nothing under it) are dropped.
MIN_PIECE_LENGTH = 40


@dataclass(frozen=True)
class Chunk:
    source: Source
    ref_id: str
    title: str
    text: str  # every text field here is masked
    url: str
    section: str  # the headings above this piece, e.g. "/A03:2021 – Injection/"
    index: int  # 0, 1, 2 ... within one item


def load_items(data_dir: Path, guides_dir: Path) -> list[KnowledgeItem]:
    """Every *.jsonl file in data_dir, plus the Markdown tool guides."""
    items = []
    for path in sorted(data_dir.glob("*.jsonl")):
        items.extend(read_items(path))
    items.extend(tool_guide_items(guides_dir))
    return items


def tool_guide_items(guides_dir: Path) -> list[KnowledgeItem]:
    items = []
    for path in sorted(guides_dir.glob("*.md")):
        items.append(
            KnowledgeItem(
                source=Source.TOOL_GUIDE,
                ref_id=path.stem,
                title=path.stem,
                text=path.read_text(encoding="utf-8"),
                text_format=TextFormat.MARKDOWN,
            )
        )
    return items


def make_chunks(items: list[KnowledgeItem]) -> list[Chunk]:
    chunks = []
    for item in items:
        chunks.extend(item_chunks(item))
    return chunks


def item_chunks(item: KnowledgeItem) -> list[Chunk]:
    if item.text_format == TextFormat.TEXT:
        return [chunk(item, item.text, section="/", index=0)]
    nodes = MarkdownNodeParser().get_nodes_from_documents([Document(text=item.text)])
    pieces = [node for node in nodes if len(node.get_content().strip()) >= MIN_PIECE_LENGTH]
    return [
        chunk(item, node.get_content(), section=node.metadata.get("header_path", "/"), index=i)
        for i, node in enumerate(pieces)
    ]


def chunk(item: KnowledgeItem, text: str, section: str, index: int) -> Chunk:
    """Every text field is masked: a secret can sit in a heading (section), a
    tool guide's file name (ref_id) or a link (url), not only in the text."""
    return Chunk(
        source=item.source,
        ref_id=masked(item.ref_id),
        title=masked(item.title),
        text=masked(text.strip()),
        url=masked(item.url),
        section=masked(section),
        index=index,
    )


def masked(text: str) -> str:
    return mask_secrets(text)[0]
