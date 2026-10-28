"""Where the knowledge files live."""

from pathlib import Path

# services/ai/data/
DATA_DIR = Path(__file__).resolve().parents[3] / "data"
# The full download: git-ignored, made by `python -m reconix_ai.knowledge.download`.
FULL_DATA_DIR = DATA_DIR / "knowledge"
# A small committed sample, so tests and a fresh install work offline.
SAMPLE_DATA_DIR = DATA_DIR / "knowledge-sample"
# One Markdown guide per tool (owner: Youlong).
TOOL_GUIDES_DIR = DATA_DIR / "tool-guides"


def knowledge_data_dir() -> Path:
    """The full download if it is there, else the committed sample."""
    if any(FULL_DATA_DIR.glob("*.jsonl")):
        return FULL_DATA_DIR
    return SAMPLE_DATA_DIR
