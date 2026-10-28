from pathlib import Path

from reconix_api.services.findings import READERS, parse_run

FIXTURES = Path(__file__).parents[2] / "fixtures"


def test_parse_run_picks_the_reader_by_tool_name():
    output = (FIXTURES / "nuclei" / "juice_shop.jsonl").read_text()
    found, _ = parse_run("NUCLEI", output)
    assert len(found) == 3


def test_every_reader_is_named_like_its_kali_tool():
    assert all(name == name.lower() for name in READERS)
    assert {"nmap", "nuclei", "semgrep", "gitleaks"} <= READERS.keys()


def test_tool_without_a_reader_gives_no_findings():
    assert parse_run("whatweb", "anything") == ([], 0)
