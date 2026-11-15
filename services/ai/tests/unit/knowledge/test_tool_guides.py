"""The tool guides in data/tool-guides are knowledge-base content: one per catalog tool,
chunked by the same code the ingest uses, and clean under secret masking."""

from reconix_ai.harness import mask_secrets
from reconix_ai.harness.catalog import tool_names
from reconix_ai.knowledge.chunks import MIN_PIECE_LENGTH, item_chunks, tool_guide_items
from reconix_ai.knowledge.paths import TOOL_GUIDES_DIR

# The chunker cuts a guide at these headings; a piece shorter than MIN_PIECE_LENGTH is dropped.
SECTIONS = ("When to use", "Key options", "Output", "Risk notes")


def test_every_catalog_tool_has_a_guide() -> None:
    written = {path.stem.lower() for path in TOOL_GUIDES_DIR.glob("*.md")}
    missing = sorted(tool_names() - written)
    assert not missing, f"no tool guide in data/tool-guides for: {', '.join(missing)}"


def test_every_guide_has_the_four_sections_in_order() -> None:
    for item in tool_guide_items(TOOL_GUIDES_DIR):
        headings = [line for line in item.text.splitlines() if line.startswith("#")]
        expected = [f"# {item.ref_id}", *(f"## {section}" for section in SECTIONS)]
        assert headings == expected, f"{item.ref_id}: {headings}"


def test_every_guide_is_one_piece_per_section() -> None:
    for item in tool_guide_items(TOOL_GUIDES_DIR):
        chunks = item_chunks(item)
        assert len(chunks) == len(SECTIONS), f"{item.ref_id}: {[chunk.section for chunk in chunks]}"
        assert all(len(chunk.text) >= MIN_PIECE_LENGTH for chunk in chunks), item.ref_id


def test_no_guide_trips_secret_masking() -> None:
    """A guide holds no secrets, so masking must change nothing: a [MASKED:...] marker here
    means the wording read like a credential, and the ingest would save it corrupted."""
    for item in tool_guide_items(TOOL_GUIDES_DIR):
        masked, count = mask_secrets(item.text)
        assert count == 0 and masked == item.text, f"{item.ref_id}: {masked.count('[MASKED:')}"
