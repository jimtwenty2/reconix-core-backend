import pytest

from reconix_ai.agent.answers import BadAnswer
from reconix_ai.reports.answers import MAX_REPORT_TEXT_CHARS, read_report


def test_both_texts_are_read_and_trimmed() -> None:
    summary, method = read_report({"executive_summary": " One leak. ", "methodology": "Nmap."})

    assert (summary, method) == ("One leak.", "Nmap.")


def test_long_text_is_cut() -> None:
    summary, _ = read_report({"executive_summary": "x" * 9000, "methodology": "Nmap."})

    assert len(summary) == MAX_REPORT_TEXT_CHARS


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"executive_summary": "One leak."},
        {"executive_summary": "  ", "methodology": "Nmap."},
        {"executive_summary": ["One leak."], "methodology": "Nmap."},
    ],
)
def test_a_missing_or_empty_text_is_a_bad_answer(data: dict) -> None:
    with pytest.raises(BadAnswer):
        read_report(data)
