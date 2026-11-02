"""VS Code flow: vscode session -> send code -> path scope -> code scan -> findings.

Through the API and a real database, with the fake Kali MCP. The scan runs in the
background, so these tests keep one TestClient open (its event loop runs the scan) and
poll the scan until it ends.
"""

import asyncio
import dataclasses
import hashlib
import io
import json
import tarfile
import time
from uuid import UUID

import pytest

from reconix_api.core.interfaces import ToolName

APP_JS = b"const express = require('express');\nconst out = eval(req.query.code);\n"
CONFIG_JS = b"module.exports = { key: 'not-a-real-key' };\n"
CODE = {"src/app.js": APP_JS, "config.js": CONFIG_JS}


@pytest.fixture
def client(code_client):
    return code_client


def vscode_session(client) -> tuple[dict, str]:
    created = client.post("/sessions", json={"interface": "vscode"})
    assert created.status_code == 201, created.json()
    body = created.json()
    return {"Authorization": f"Bearer {body['token']}"}, body["session_id"]


def entries(files: dict[str, bytes]) -> list[dict]:
    return [
        {"path": path, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for path, data in files.items()
    ]


def tar_gz(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def upload(client, headers, session_id, archive: bytes):
    return client.put(
        f"/sessions/{session_id}/code",
        content=archive,
        headers={**headers, "Content-Type": "application/gzip"},
    )


def send_code(client, headers, session_id, files: dict[str, bytes]) -> dict:
    """Sync, then upload what is missing. Returns the sync answer."""
    synced = client.post(
        f"/sessions/{session_id}/code/sync", json={"files": entries(files)}, headers=headers
    )
    assert synced.status_code == 200, synced.json()
    missing = synced.json()["missing"]
    if missing:
        uploaded = upload(client, headers, session_id, tar_gz({p: files[p] for p in missing}))
        assert uploaded.status_code == 200, uploaded.json()
    return synced.json()


def code_assessment(client, headers, target: str) -> str:
    draft = {
        "max_risk": "LOW",
        "allowed_tools": ["SEMGREP", "GITLEAKS"],
        "targets": [{"type": "path", "value": target}],
    }
    session_id = client.get("/operator", headers=headers).json()["session_id"]
    scope = client.post(f"/sessions/{session_id}/scope-manifests", json=draft, headers=headers)
    assert scope.status_code == 201, scope.json()
    submitted = client.post(
        f"/scope-manifests/{scope.json()['manifest_id']}/submit",
        json={"name": "Acme Notes", "type": "source_code"},
        headers=headers,
    ).json()
    client.post(f"/approvals/{submitted['approval_id']}/approve", json={}, headers=headers)
    return submitted["assessment"]["assessment_id"]


def tool_outputs(db_app, target: str) -> None:
    mcp = db_app.state.parts["mcp"]
    mcp.outputs[ToolName.SEMGREP] = json.dumps(
        {
            "results": [
                {
                    "check_id": "javascript.lang.security.audit.eval-detected",
                    "path": f"{target}/src/app.js",
                    "start": {"line": 2, "col": 13},
                    "end": {"line": 2, "col": 35},
                    "extra": {
                        "severity": "ERROR",
                        "message": "eval() with user input.",
                        "metadata": {"cwe": ["CWE-95: Eval Injection"]},
                    },
                }
            ],
            "errors": [],
        }
    )
    mcp.outputs[ToolName.GITLEAKS] = json.dumps(
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API Key",
                "File": f"{target}/config.js",
                "StartLine": 1,
                "EndLine": 1,
                "Secret": "REDACTED",
                "Match": "key: 'REDACTED'",
                "Line": "module.exports = { key: 'REDACTED' };",
            }
        ]
    )


def start(client, headers, assessment_id, analyze: bool = False):
    return client.post(
        f"/assessments/{assessment_id}/code-scans", json={"analyze": analyze}, headers=headers
    )


def wait_for_end(client, headers, scan_id: str) -> dict:
    for _ in range(200):
        scan = client.get(f"/code-scans/{scan_id}", headers=headers).json()
        if scan["agent_runs_status"] != "RUNNING":
            return scan
        time.sleep(0.02)
    raise AssertionError("the scan did not end")


def ready_to_scan(client, db_app) -> tuple[dict, str, str]:
    headers, session_id = vscode_session(client)
    target = send_code(client, headers, session_id, CODE)["target"]
    tool_outputs(db_app, target)
    return headers, session_id, code_assessment(client, headers, target)


def event_types(db_app) -> list[str]:
    return [event.event_type for event in db_app.state.parts["audit"].events]


def slow_tools(db_app, seconds: float) -> None:
    """Every tool call takes a while, so a test can act while the scan runs."""
    fast = db_app.state.parts["mcp"].call_tool

    async def slow(job):
        await asyncio.sleep(seconds)
        return await fast(job)

    db_app.state.interfaces = dataclasses.replace(db_app.state.interfaces, call_tool=slow)


# ---------------------------------------------------------------------------
# Sessions and code
# ---------------------------------------------------------------------------


def test_vscode_sessions_can_be_listed_alone(client):
    headers, session_id = vscode_session(client)
    client.post("/sessions", json={"interface": "cli"})

    listed = client.get(
        "/sessions", params={"interface": "vscode", "session_status": "ACTIVE"}, headers=headers
    )
    assert [s["session_id"] for s in listed.json()] == [session_id]


def test_sync_and_upload_store_the_code(client, code_dir, db_app):
    headers, session_id = vscode_session(client)

    synced = send_code(client, headers, session_id, CODE)

    assert synced == {
        "missing": ["config.js", "src/app.js"],
        "target": f"/workspace/code/{session_id}",
    }
    assert (code_dir / session_id / "src/app.js").read_bytes() == APP_JS
    assert {"CODE_SYNCED", "CODE_UPLOADED"} <= set(event_types(db_app))
    # The audit holds counts, never file names.
    uploaded = [e for e in db_app.state.parts["audit"].events if e.event_type == "CODE_UPLOADED"]
    assert uploaded[0].details == {"files": 2, "size_bytes": len(APP_JS) + len(CONFIG_JS)}


def test_a_second_sync_asks_only_for_changed_files_and_drops_deleted_ones(client, code_dir):
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, CODE)

    changed = {"src/app.js": b"const fixed = true;\n", "README.md": b"# Acme\n"}
    synced = send_code(client, headers, session_id, changed)

    assert synced["missing"] == ["README.md", "src/app.js"]
    assert not (code_dir / session_id / "config.js").exists()
    assert (code_dir / session_id / "src/app.js").read_bytes() == b"const fixed = true;\n"


def test_code_goes_only_to_your_own_session(client):
    headers, _ = vscode_session(client)
    _, other_session = vscode_session(client)

    synced = client.post(
        f"/sessions/{other_session}/code/sync", json={"files": entries(CODE)}, headers=headers
    )
    uploaded = upload(client, headers, other_session, tar_gz(CODE))

    assert synced.status_code == 403
    assert uploaded.status_code == 403
    assert uploaded.json()["code"] == "NOT_YOUR_SESSION"


def test_bad_uploads_are_refused_and_change_nothing(client, code_dir):
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, CODE)

    escape = upload(client, headers, session_id, tar_gz({"../escape.js": b"x"}))
    not_tar = upload(client, headers, session_id, b"not a tar.gz")
    too_big = upload(client, headers, session_id, b"x" * (1024 * 1024 + 1))  # limit: 1 MB
    bad_sync = client.post(
        f"/sessions/{session_id}/code/sync",
        json={"files": [{"path": "/etc/passwd", "size_bytes": 1, "sha256": "0" * 64}]},
        headers=headers,
    )

    assert escape.status_code == 422
    assert escape.json()["code"] == "INVALID_CODE_UPLOAD"
    assert not_tar.status_code == 422
    assert too_big.status_code == 413
    assert too_big.json()["code"] == "UPLOAD_TOO_LARGE"
    assert bad_sync.status_code == 422
    assert not (code_dir / "escape.js").exists()
    assert (code_dir / session_id / "src/app.js").read_bytes() == APP_JS


def test_closing_the_session_deletes_its_code(client, code_dir):
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, CODE)

    closed = client.post(f"/sessions/{session_id}/close", headers=headers)

    assert closed.status_code == 200
    assert not (code_dir / session_id).exists()


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["/etc", "/workspace/code/../../etc", "/workspace/code/"])
def test_a_path_target_must_be_under_the_code_folder(client, value):
    headers, session_id = vscode_session(client)
    draft = {"allowed_tools": ["SEMGREP"], "targets": [{"type": "path", "value": value}]}

    response = client.post(f"/sessions/{session_id}/scope-manifests", json=draft, headers=headers)

    assert response.status_code == 422


def test_an_approved_path_target_becomes_a_repo_path(client, db_app):
    headers, session_id, assessment_id = ready_to_scan(client, db_app)

    scope = db_app.state.interfaces.get_approved_scope(UUID(assessment_id))

    assert scope.repo_paths == [f"/workspace/code/{session_id}"]


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def test_scan_runs_both_tools_and_returns_editor_ready_findings(client, db_app, code_dir):
    headers, session_id, assessment_id = ready_to_scan(client, db_app)

    started = start(client, headers, assessment_id)
    assert started.status_code == 202, started.json()
    scan = wait_for_end(client, headers, started.json()["agent_run_id"])

    assert scan["agent_runs_status"] == "COMPLETED"
    assert (scan["stage"], scan["progress"], scan["error"]) == ("DONE", 100, None)
    assert scan["counts"]["HIGH"] == 1
    assert scan["counts"]["UNKNOWN"] == 1  # gitleaks gives no severity
    jobs = db_app.state.parts["mcp"].jobs
    assert [(job.tool, job.target) for job in jobs] == [
        (ToolName.SEMGREP, f"/workspace/code/{session_id}"),
        (ToolName.GITLEAKS, f"/workspace/code/{session_id}"),
    ]

    found = client.get(f"/code-scans/{scan['agent_run_id']}/findings", headers=headers).json()
    by_path = {finding["path"]: finding for finding in found}
    eval_hit = by_path["src/app.js"]
    assert (eval_hit["line"], eval_hit["end_line"]) == (2, 2)
    assert eval_hit["rule_id"] == "javascript.lang.security.audit.eval-detected"
    assert eval_hit["snippet"] == "const out = eval(req.query.code);"
    assert eval_hit["file_sha256"] == hashlib.sha256(APP_JS).hexdigest()
    assert eval_hit["cwe_ids"] == ["CWE-95"]
    leak = by_path["config.js"]
    assert (leak["line"], leak["rule_id"], leak["snippet"]) == (1, "generic-api-key", None)
    assert "not-a-real-key" not in json.dumps(found)

    events = event_types(db_app)
    assert "CODE_SCAN_STARTED" in events
    assert events.count("TOOL_RUN_STARTED") == 2
    assert events[-1] == "AGENT_RUN_COMPLETED"


def test_scan_with_analysis_links_the_analyze_run(client, db_app):
    headers, _, assessment_id = ready_to_scan(client, db_app)

    started = start(client, headers, assessment_id, analyze=True)
    scan = wait_for_end(client, headers, started.json()["agent_run_id"])

    assert scan["agent_runs_status"] == "COMPLETED"
    assert scan["notes"] == []
    analysis = client.get(f"/agent-runs/{scan['analysis_run_id']}", headers=headers).json()
    assert analysis["plan"]["task"] == "ANALYZE"
    assert len(analysis["plan"]["analysis"]) == 2


def test_a_rescan_lists_only_what_it_found_again(client, db_app):
    headers, session_id, assessment_id = ready_to_scan(client, db_app)
    first = wait_for_end(
        client, headers, start(client, headers, assessment_id).json()["agent_run_id"]
    )
    db_app.state.parts["mcp"].outputs[ToolName.GITLEAKS] = "[]"  # the key was removed

    second = wait_for_end(
        client, headers, start(client, headers, assessment_id).json()["agent_run_id"]
    )

    found = client.get(f"/code-scans/{second['agent_run_id']}/findings", headers=headers).json()
    assert [finding["path"] for finding in found] == ["src/app.js"]
    assert first["counts"]["UNKNOWN"] == 1
    assert second["counts"]["UNKNOWN"] == 0


def test_scan_needs_code_first(client):
    headers, session_id = vscode_session(client)
    assessment_id = code_assessment(client, headers, f"/workspace/code/{session_id}")

    response = start(client, headers, assessment_id)

    assert response.status_code == 422
    assert response.json()["code"] == "NO_CODE"


def test_scan_fails_when_no_tool_finishes(client, db_app):
    headers, _, assessment_id = ready_to_scan(client, db_app)
    db_app.state.parts["mcp"].down = True

    scan = wait_for_end(
        client, headers, start(client, headers, assessment_id).json()["agent_run_id"]
    )

    assert scan["agent_runs_status"] == "FAILED"
    assert scan["error"] == "TOOLS_FAILED"
    assert scan["notes"] == ["SEMGREP FAILED", "GITLEAKS FAILED"]


def test_cancel_stops_the_scan_before_its_next_tool(client, db_app):
    headers, _, assessment_id = ready_to_scan(client, db_app)
    slow_tools(db_app, 0.3)
    scan_id = start(client, headers, assessment_id).json()["agent_run_id"]

    cancelled = client.post(f"/code-scans/{scan_id}/cancel", headers=headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["agent_runs_status"] == "CANCELLED"
    time.sleep(0.6)  # the running semgrep call ends

    scan = client.get(f"/code-scans/{scan_id}", headers=headers).json()
    assert scan["agent_runs_status"] == "CANCELLED"
    assert [job.tool for job in db_app.state.parts["mcp"].jobs] == [ToolName.SEMGREP]
    again = client.post(f"/code-scans/{scan_id}/cancel", headers=headers)
    assert again.status_code == 409
    assert again.json()["code"] == "SCAN_ENDED"


def test_code_cannot_change_and_no_second_scan_starts_while_one_runs(client, db_app):
    headers, session_id, assessment_id = ready_to_scan(client, db_app)
    slow_tools(db_app, 0.3)
    scan_id = start(client, headers, assessment_id).json()["agent_run_id"]

    second = start(client, headers, assessment_id)
    uploaded = upload(client, headers, session_id, tar_gz({"new.js": b"x"}))

    assert second.status_code == 409
    assert second.json()["code"] == "SCAN_RUNNING"
    assert uploaded.status_code == 409
    assert uploaded.json()["code"] == "SCAN_RUNNING"
    assert wait_for_end(client, headers, scan_id)["agent_runs_status"] == "COMPLETED"


def test_unknown_scan_ids_answer_404(client, db_app):
    headers, _ = vscode_session(client)
    other_run = "00000000-0000-0000-0000-000000000000"

    assert client.get(f"/code-scans/{other_run}", headers=headers).status_code == 404
    assert client.get(f"/code-scans/{other_run}/findings", headers=headers).status_code == 404


def test_closing_the_session_cancels_its_running_scan(client, db_app):
    headers, session_id, assessment_id = ready_to_scan(client, db_app)
    slow_tools(db_app, 0.3)
    scan_id = start(client, headers, assessment_id).json()["agent_run_id"]

    closed = client.post(f"/sessions/{session_id}/close", headers=headers)
    assert closed.status_code == 200
    time.sleep(0.6)  # the running semgrep call ends

    other_headers, _ = vscode_session(client)  # the closed session's token no longer works
    scan = client.get(f"/code-scans/{scan_id}", headers=other_headers).json()
    assert scan["agent_runs_status"] == "CANCELLED"
    assert [job.tool for job in db_app.state.parts["mcp"].jobs] == [ToolName.SEMGREP]
    assert event_types(db_app).count("AGENT_RUN_CANCELLED") == 1


def test_a_scope_that_excludes_a_code_folder_cannot_be_scanned(client, db_app):
    headers, session_id = vscode_session(client)
    target = send_code(client, headers, session_id, CODE)["target"]
    draft = {
        "max_risk": "LOW",
        "allowed_tools": ["SEMGREP", "GITLEAKS"],
        "targets": [
            {"type": "path", "value": target},
            {"type": "path", "value": f"{target}/config", "excluded": True},
        ],
    }
    scope = client.post(f"/sessions/{session_id}/scope-manifests", json=draft, headers=headers)
    submitted = client.post(
        f"/scope-manifests/{scope.json()['manifest_id']}/submit",
        json={"name": "Acme Notes", "type": "source_code"},
        headers=headers,
    ).json()
    client.post(f"/approvals/{submitted['approval_id']}/approve", json={}, headers=headers)

    response = start(client, headers, submitted["assessment"]["assessment_id"])

    assert response.status_code == 422
    assert response.json()["code"] == "EXCLUDED_PATH_NOT_SUPPORTED"
    assert db_app.state.parts["mcp"].jobs == []
