import pytest

from reconix_ai.agent.prompts import PROMPTS_DIR, read_markdown

PROMPT_FILES = ["system.md", "understand.md", "plan.md", "analyze.md", "report.md", "chat.md"]
# findings.severity_status in ERD V3: NONE, never INFO.
SEVERITY_VALUES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]


@pytest.mark.parametrize("name", PROMPT_FILES)
def test_every_prompt_is_written(name: str) -> None:
    text = read_markdown(PROMPTS_DIR / name)

    assert "TODO" not in text
    assert len(text.splitlines()) > 3


@pytest.mark.parametrize("name", ["analyze.md", "report.md", "chat.md"])
def test_task_prompts_ask_for_json(name: str) -> None:
    assert "JSON object" in read_markdown(PROMPTS_DIR / name)


def test_analysis_uses_the_erd_severity_values() -> None:
    text = read_markdown(PROMPTS_DIR / "analyze.md")

    for value in SEVERITY_VALUES:
        assert value in text
    assert "INFO" not in text and "NEEDS_REVIEW" not in text


def test_system_prompt_marks_findings_as_data() -> None:
    text = read_markdown(PROMPTS_DIR / "system.md")

    for tag in ["<goal>", "<reference_data>", "<tool_results>", "<findings>"]:
        assert tag in text


def test_prompts_folder_has_no_other_files() -> None:
    names = sorted(path.name for path in PROMPTS_DIR.glob("*.md"))

    assert names == sorted(PROMPT_FILES)
