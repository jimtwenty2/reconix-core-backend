"""A source-code scope runs the Core API code-scan flow: upload, scan, findings."""

import io
import tarfile

import pytest

from reconix import store
from reconix.core_api import code_scan
from reconix.core_api.client import CoreApiError

from .support import decide, drive_live, play_until_gate


@pytest.fixture
def code_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(code_scan, "POLL_SECONDS", 0)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("cur.execute(q + user)\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("skip")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("skip")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "k.txt").write_text("skip")
    (tmp_path / "link").symlink_to(tmp_path / "app" / "db.py")
    return tmp_path


def _run(target):
    store.start_run(f"Review the source code in {target}", "source")
    assert play_until_gate() == "scope"
    store.approve_scope()
    while play_until_gate() is not None:
        decide("plan")


def test_collect_skips_left_out_folders_links_and_excluded(code_dir):
    files = code_scan.collect(str(code_dir), [".git", "secrets"])
    assert sorted(files) == ["app/db.py"]


def test_a_local_folder_is_uploaded_scanned_and_its_findings_shown(fake_api, code_dir):
    _run(code_dir)
    paths = fake_api.paths()
    assert any(p.endswith("/code/sync") for p in paths)
    assert any(p.startswith("PUT /sessions/") and p.endswith("/code") for p in paths)
    with tarfile.open(fileobj=io.BytesIO(fake_api.uploads[0])) as tar:
        assert tar.getnames() == ["app/db.py"]
    scan_body = fake_api.bodies("POST", "/sessions/s-0002/code-scans")[0]
    assert scan_body["analyze"] is True and scan_body["tools"] == ["SEMGREP", "GITLEAKS", "TRIVY"]
    found = store.list_findings()
    assert [f.severity for f in found] == ["HIGH"]
    assert found[0].path == "app/db.py:12" and found[0].remediation == "Use parameters."
    assert found[0].evidence[-1] == "cur.execute(q + user)"
    assert store.is_completed()
    assert not any("/scope-manifests" in p for p in paths)


def test_an_unchanged_rescan_uploads_nothing(fake_api, code_dir):
    files = code_scan.collect(str(code_dir), ["secrets"])
    sid = code_scan.connect.session_id()
    assert code_scan.upload(sid, files)[0] == 1
    assert code_scan.upload(sid, files)[0] == 0
    assert len(fake_api.uploads) == 1


@pytest.mark.parametrize("status,code", [(401, "UNAUTHORIZED"), (422, "INVALID_CODE_UPLOAD"),
                                         (413, "UPLOAD_TOO_LARGE")])
def test_api_refusals_are_shown_as_they_came(fake_api, code_dir, status, code):
    fake_api.fail_on["PUT /sessions/"] = (status, code, "refused by the API")
    store.start_run(f"Review the source code in {code_dir}", "source")
    play_until_gate()
    store.approve_scope()
    while play_until_gate() is not None:
        pass
    live = store.get_assessment().live
    assert live.failed == f"{code}: refused by the API"
    assert store.list_findings() == [] and not store.is_completed()


def test_a_failed_scan_is_an_error_not_empty_findings(fake_api, code_dir, monkeypatch):
    monkeypatch.setattr(fake_api, "code_polls", 0)
    original = fake_api._code_scan_out

    def failed(run_id):
        return {**original(run_id), "agent_runs_status": "FAILED", "error": "ALL_TOOLS_FAILED"}

    monkeypatch.setattr(fake_api, "_code_scan_out", failed)
    _run(code_dir)
    assert store.get_assessment().live.failed.startswith("ALL_TOOLS_FAILED")
    assert store.list_findings() == []


def test_the_api_down_is_said_plainly(fake_api, code_dir):
    store.start_run(f"Review the source code in {code_dir}", "source")
    play_until_gate()
    store.approve_scope()
    fake_api.down = True
    while play_until_gate() is not None:
        pass
    assert "not running" in store.get_assessment().live.failed


def test_a_repo_url_shows_the_apis_clone_error(fake_api):
    store.start_run("Review the source code of https://github.com/acme/app", "source")
    play_until_gate()
    store.approve_scope()
    while play_until_gate() is not None:
        pass
    assert store.get_assessment().live.failed.startswith("GIT_NOT_FOUND")
    assert not fake_api.uploads


def test_a_missing_folder_is_refused_before_any_upload(fake_api, tmp_path):
    with pytest.raises(CoreApiError) as caught:
        code_scan.run_scan(str(tmp_path / "nope") + "/", [], None, lambda: "s")
    assert caught.value.code == "FOLDER_NOT_FOUND" and not fake_api.calls


def test_progress_lines_reach_the_log(fake_api, code_dir, monkeypatch):
    monkeypatch.setattr(fake_api, "code_polls", 2)
    seen = []
    store.start_run(f"Review the source code in {code_dir}", "source")
    play_until_gate()
    store.approve_scope()
    store.advance()
    while store.advance():
        pass
    job = store.next_live_job()
    job.on_progress = lambda text: (seen.append(text), job.progress(text))
    job.apply(job.fetch())
    assert any(t.startswith("Uploading 1 files") for t in seen)
    assert any("Scanning · 40%" in t for t in seen)
    assert drive_live() is False
