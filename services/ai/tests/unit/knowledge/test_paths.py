from pathlib import Path

import pytest

from reconix_ai.knowledge import paths


def test_uses_the_sample_when_there_is_no_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "FULL_DATA_DIR", tmp_path / "knowledge")

    assert paths.knowledge_data_dir() == paths.SAMPLE_DATA_DIR


def test_uses_the_full_download_when_it_is_there(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    full = tmp_path / "knowledge"
    full.mkdir()
    (full / "cve.jsonl").write_text("", "utf-8")
    monkeypatch.setattr(paths, "FULL_DATA_DIR", full)

    assert paths.knowledge_data_dir() == full


def test_sample_is_in_the_repo() -> None:
    assert sorted(p.name for p in paths.SAMPLE_DATA_DIR.glob("*.jsonl")) == [
        "attack.jsonl",
        "cve.jsonl",
        "cwe.jsonl",
        "owasp_api_top10.jsonl",
        "owasp_top10.jsonl",
    ]
