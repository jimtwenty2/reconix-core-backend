"""Session code scans: auto scope, the 7 tools, paths and tools, incremental rescans.

Through the API and a real database, with the fake Kali MCP. Its tools read the copy
folder each run gets (<session>/_reconix_scan_<run8>/{all,changed}) on disk, so what a
tool finds depends on which files that copy holds, as with the real Kali.
"""

import json
import time
from pathlib import Path
from uuid import UUID

import pytest

from reconix_api.core.interfaces import ToolName
from reconix_api.services import code_scans
from tests.integration.test_code_scan_flow import (
    code_assessment,
    event_types,
    send_code,
    slow_tools,
    vscode_session,
    wait_for_end,
)

APP_PY = b"import os\nos.system(input())  # eval-me\n"
UTIL_PY = b"def add(a, b):\n    return a + b\n"
SETTINGS_PY = b"API_KEY = 'not-a-real-key'\n"
REQUIREMENTS = b"flask==0.12.2\n"
CODE = {
    "src/app.py": APP_PY,
    "src/util.py": UTIL_PY,
    "settings.py": SETTINGS_PY,
    "requirements.txt": REQUIREMENTS,
}
SONAR_LOG = (
    "INFO  ANALYSIS SUCCESSFUL, you can find the results at: "
    "http://localhost:9000/dashboard?id=all\nINFO  EXECUTION SUCCESS\n"
)
ALL_TOOLS = ["SEMGREP", "GITLEAKS", "TRIVY", "GRYPE", "OSV_SCANNER", "SYFT", "SONAR_SCAN"]


@pytest.fixture
def client(code_client):
    return code_client


def copy_files(code_dir: Path, target: str) -> dict[str, bytes]:
    """The files in a tool's target folder, read on disk as Kali would."""
    folder = Path(target.replace("/workspace/code", str(code_dir), 1))
    return {
        file.relative_to(folder).as_posix(): file.read_bytes()
        for file in folder.rglob("*")
        if file.is_file() and file.name != ".semgrepignore"
    }


def kali_tools(db_app, code_dir: Path) -> dict[str, list[str]]:
    """Fake tools that find something in the files their target holds. Returns, per
    tool, the file names each of its calls read."""
    mcp = db_app.state.parts["mcp"]
    read: dict[str, list[str]] = {}

    def semgrep(job):
        files = copy_files(code_dir, job.target)
        read.setdefault("SEMGREP", []).extend(sorted(files))
        results = [
            {
                "check_id": "python.lang.security.audit.dangerous-system-call",
                "path": f"{job.target}/{path}",
                "start": {"line": 2, "col": 1},
                "end": {"line": 2, "col": 20},
                "extra": {"severity": "ERROR", "message": "os.system with input."},
            }
            for path, data in files.items()
            if b"os.system" in data
        ]
        return json.dumps({"results": results, "errors": []})

    def gitleaks(job):
        files = copy_files(code_dir, job.target)
        read.setdefault("GITLEAKS", []).extend(sorted(files))
        leaks = [
            {
                "RuleID": "generic-api-key",
                "File": f"{job.target}/{path}",
                "StartLine": 1,
                "EndLine": 1,
                "Secret": "REDACTED",
                "Match": "API_KEY = 'REDACTED'",
            }
            for path, data in files.items()
            if b"API_KEY" in data
        ]
        return json.dumps(leaks)

    def trivy(job):
        files = copy_files(code_dir, job.target)
        read.setdefault("TRIVY", []).extend(sorted(files))
        vulnerabilities = [
            {
                "VulnerabilityID": "CVE-2018-1000656",
                "PkgName": "flask",
                "InstalledVersion": version.decode(),
                "Severity": "HIGH",
                "Title": "flask: Denial of Service via crafted JSON",
            }
            for line in files.get("requirements.txt", b"").splitlines()
            if line.startswith(b"flask==") and (version := line.split(b"==")[1]) < b"1"
        ]
        results = [{"Target": "requirements.txt", "Vulnerabilities": vulnerabilities}]
        return json.dumps(
            {"ArtifactName": job.target, "ArtifactType": "filesystem", "Results": results}
        )

    mcp.outputs[ToolName.SEMGREP] = semgrep
    mcp.outputs[ToolName.GITLEAKS] = gitleaks
    mcp.outputs[ToolName.TRIVY] = trivy
    mcp.outputs[ToolName.GRYPE] = json.dumps({"matches": []})
    mcp.outputs[ToolName.OSV_SCANNER] = json.dumps({"results": []})
    mcp.outputs[ToolName.SYFT] = json.dumps({"artifacts": [{"name": "flask"}, {"name": "x"}]})
    mcp.outputs[ToolName.SONAR_SCAN] = SONAR_LOG
    return read


def scan(client, headers, session_id: str, **body) -> dict:
    started = client.post(f"/sessions/{session_id}/code-scans", json=body, headers=headers)
    assert started.status_code == 202, started.json()
    return wait_for_end(client, headers, started.json()["agent_run_id"])


def tools_run(db_app, since: int = 0) -> list[str]:
    return [job.tool for job in db_app.state.parts["mcp"].jobs[since:]]


def findings(client, headers, scan_id: str) -> list[dict]:
    response = client.get(f"/code-scans/{scan_id}/findings", headers=headers)
    assert response.status_code == 200, response.json()
    return sorted(response.json(), key=lambda finding: finding["path"])


def ready(client, db_app, code_dir) -> tuple[dict, str, dict[str, list[str]]]:
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, CODE)
    return headers, session_id, kali_tools(db_app, code_dir)


# ---------------------------------------------------------------------------
# Auto scope
# ---------------------------------------------------------------------------


def test_a_session_scan_approves_its_own_code_folder_once(client, db_app, code_dir):
    headers, session_id, _ = ready(client, db_app, code_dir)

    first = scan(client, headers, session_id)
    send_code(client, headers, session_id, {**CODE, "src/util.py": b"x = 1\n"})
    second = scan(client, headers, session_id)

    assert first["agent_runs_status"] == "COMPLETED", first
    assert second["assessment_id"] == first["assessment_id"]  # the scope is reused
    approved = [e for e in db_app.state.parts["audit"].events if e.event_type == "SCOPE_APPROVED"]
    assert len(approved) == 1
    assert approved[0].details["reason"] == "CODE_SESSION_FOLDER"
    scope = db_app.state.interfaces.get_approved_scope(UUID(first["assessment_id"]))
    assert scope.repo_paths == [f"/workspace/code/{session_id}"]
    assert scope.allowed_tools == ALL_TOOLS
    assert tools_run(db_app)[:8] == ["tools_info", *ALL_TOOLS]
    assert "SYFT 2 packages" in first["notes"]
    assert "SONAR_SCAN OK http://localhost:9000/dashboard?id=all" in first["notes"]


def test_the_first_scan_finds_code_secret_and_dependency_problems(client, db_app, code_dir):
    headers, session_id, _ = ready(client, db_app, code_dir)

    done = scan(client, headers, session_id)

    found = findings(client, headers, done["agent_run_id"])
    assert [(f["path"], f["tools"]) for f in found] == [
        ("requirements.txt", ["TRIVY"]),
        ("settings.py", ["GITLEAKS"]),
        ("src/app.py", ["SEMGREP"]),
    ]
    assert done["counts"]["HIGH"] == 3
    assert not list((code_dir / session_id).glob("_reconix_scan_*"))  # the copy is gone


def test_another_scope_on_the_session_is_not_replaced(client, db_app, code_dir):
    headers, session_id, _ = ready(client, db_app, code_dir)
    code_assessment(client, headers, f"/workspace/code/{session_id}")  # SEMGREP, GITLEAKS

    refused = client.post(f"/sessions/{session_id}/code-scans", json={}, headers=headers)
    two_tools = scan(client, headers, session_id, tools=["SEMGREP", "GITLEAKS"])

    assert refused.status_code == 409
    assert refused.json()["code"] == "CODE_SCOPE_MISMATCH"
    assert two_tools["agent_runs_status"] == "COMPLETED"


def test_only_your_own_session_is_scanned(client, db_app, code_dir):
    headers, _, _ = ready(client, db_app, code_dir)
    _, other_session = vscode_session(client)

    response = client.post(f"/sessions/{other_session}/code-scans", json={}, headers=headers)

    assert response.status_code == 403
    assert response.json()["code"] == "NOT_YOUR_SESSION"


# ---------------------------------------------------------------------------
# paths and tools
# ---------------------------------------------------------------------------


def test_paths_and_tools_limit_the_scan(client, db_app, code_dir):
    headers, session_id, read = ready(client, db_app, code_dir)

    done = scan(client, headers, session_id, paths=["src", "settings.py"], tools=["SEMGREP"])

    assert done["agent_runs_status"] == "COMPLETED"
    assert tools_run(db_app) == ["tools_info", "SEMGREP"]
    assert read["SEMGREP"] == ["settings.py", "src/app.py", "src/util.py"]
    assert [f["path"] for f in findings(client, headers, done["agent_run_id"])] == ["src/app.py"]


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"paths": ["../etc"]}, "VALIDATION_ERROR"),
        ({"paths": ["/etc"]}, "VALIDATION_ERROR"),
        ({"tools": ["NMAP"]}, "VALIDATION_ERROR"),
        ({"tools": []}, "VALIDATION_ERROR"),
        ({"paths": ["missing"]}, "PATH_NOT_FOUND"),
    ],
)
def test_bad_paths_and_tools_are_refused(client, db_app, code_dir, body, code):
    headers, session_id, _ = ready(client, db_app, code_dir)

    response = client.post(f"/sessions/{session_id}/code-scans", json=body, headers=headers)

    assert response.status_code == 422
    assert response.json()["code"] == code


def test_a_tool_the_scope_does_not_allow_is_a_note(client, db_app, code_dir):
    headers, session_id, _ = ready(client, db_app, code_dir)
    assessment_id = code_assessment(client, headers, f"/workspace/code/{session_id}")

    started = client.post(
        f"/assessments/{assessment_id}/code-scans",
        json={"tools": ["SEMGREP", "TRIVY"], "analyze": False},
        headers=headers,
    )
    done = wait_for_end(client, headers, started.json()["agent_run_id"])

    assert done["agent_runs_status"] == "COMPLETED"
    assert done["notes"] == ["TRIVY BLOCKED TOOL_NOT_ALLOWED"]  # the reason is kept
    assert tools_run(db_app) == ["tools_info", "SEMGREP"]
    assert "ACTION_BLOCKED" in event_types(db_app)


# ---------------------------------------------------------------------------
# Rescans
# ---------------------------------------------------------------------------


def test_a_rescan_reads_only_the_changed_file_and_keeps_the_rest(client, db_app, code_dir):
    headers, session_id, read = ready(client, db_app, code_dir)
    first = scan(client, headers, session_id)
    before = len(db_app.state.parts["mcp"].jobs)
    read.clear()

    send_code(client, headers, session_id, {**CODE, "src/app.py": b"print('fixed')\n"})
    second = scan(client, headers, session_id)

    assert tools_run(db_app, before) == ["tools_info", "SEMGREP", "GITLEAKS", "SONAR_SCAN"]
    assert read == {"SEMGREP": ["src/app.py"], "GITLEAKS": ["src/app.py"]}
    found = findings(client, headers, second["agent_run_id"])
    assert [(f["path"], f["tools"]) for f in found] == [
        ("requirements.txt", ["TRIVY"]),  # kept: the lockfile did not change
        ("settings.py", ["GITLEAKS"]),  # kept: the file did not change
    ]
    assert first["counts"]["HIGH"] == 3
    assert second["counts"]["HIGH"] == 2


def test_a_lockfile_change_runs_the_dependency_tools(client, db_app, code_dir):
    headers, session_id, read = ready(client, db_app, code_dir)
    scan(client, headers, session_id)
    before = len(db_app.state.parts["mcp"].jobs)
    read.clear()

    send_code(client, headers, session_id, {**CODE, "requirements.txt": b"flask==2.3.3\n"})
    second = scan(client, headers, session_id)

    assert tools_run(db_app, before) == ["tools_info", *ALL_TOOLS]
    assert read["SEMGREP"] == ["requirements.txt"]
    assert read["TRIVY"] == sorted(CODE)  # every file of the scan
    found = findings(client, headers, second["agent_run_id"])
    assert [f["path"] for f in found] == ["settings.py", "src/app.py"]  # flask 2 is fixed


def test_a_rescan_with_no_change_calls_kali_not_at_all(client, db_app, code_dir):
    headers, session_id, _ = ready(client, db_app, code_dir)
    first = scan(client, headers, session_id)
    before = len(db_app.state.parts["mcp"].jobs)

    second = scan(client, headers, session_id)

    assert second["agent_runs_status"] == "COMPLETED"
    assert tools_run(db_app, before) == []
    assert second["counts"] == first["counts"]
    assert findings(client, headers, second["agent_run_id"]) == findings(
        client, headers, first["agent_run_id"]
    )


def test_new_tool_versions_make_a_full_scan(client, db_app, code_dir):
    headers, session_id, read = ready(client, db_app, code_dir)
    first = scan(client, headers, session_id)
    before = len(db_app.state.parts["mcp"].jobs)
    read.clear()
    db_app.state.parts["mcp"].versions["scanners"] = "semgrep==1.184.0\n"

    send_code(client, headers, session_id, {**CODE, "src/util.py": b"x = 1\n"})
    second = scan(client, headers, session_id)

    assert tools_run(db_app, before) == ["tools_info", *ALL_TOOLS]
    assert read["SEMGREP"] == sorted(CODE)
    # Found again from another copy folder: the same findings, deduped by their real path.
    ids = [f["finding_id"] for f in findings(client, headers, first["agent_run_id"])]
    assert [f["finding_id"] for f in findings(client, headers, second["agent_run_id"])] == ids


def test_a_new_tool_makes_a_full_scan(client, db_app, code_dir):
    headers, session_id, read = ready(client, db_app, code_dir)
    scan(client, headers, session_id, tools=["SEMGREP"])
    before = len(db_app.state.parts["mcp"].jobs)

    scan(client, headers, session_id, tools=["SEMGREP", "GITLEAKS"])

    assert tools_run(db_app, before) == ["tools_info", "SEMGREP", "GITLEAKS"]
    assert read["GITLEAKS"] == sorted(CODE)


def test_a_file_a_failed_tool_missed_is_read_again_next_time(client, db_app, code_dir):
    headers, session_id, read = ready(client, db_app, code_dir)
    scan(client, headers, session_id, tools=["SEMGREP", "GITLEAKS"])
    mcp = db_app.state.parts["mcp"]
    working = mcp.outputs[ToolName.GITLEAKS]
    mcp.outputs[ToolName.GITLEAKS] = lambda job: (_ for _ in ()).throw(ConnectionError())

    send_code(client, headers, session_id, {**CODE, "settings.py": b"API_KEY = 'other'\n"})
    failed = scan(client, headers, session_id, tools=["SEMGREP", "GITLEAKS"])
    mcp.outputs[ToolName.GITLEAKS] = working
    read.clear()
    third = scan(client, headers, session_id, tools=["SEMGREP", "GITLEAKS"])

    assert failed["notes"] == ["GITLEAKS FAILED"]
    assert read == {"SEMGREP": ["settings.py"], "GITLEAKS": ["settings.py"]}
    assert [f["path"] for f in findings(client, headers, third["agent_run_id"])] == [
        "settings.py",
        "src/app.py",
    ]


def test_a_paths_scan_leaves_the_other_files_as_they_were(client, db_app, code_dir):
    """Files outside the paths are not deleted: a no-change paths scan, then a no-change
    full scan, call Kali not at all and keep every finding."""
    headers, session_id, _ = ready(client, db_app, code_dir)
    first = scan(client, headers, session_id)
    before = len(db_app.state.parts["mcp"].jobs)

    part = scan(client, headers, session_id, paths=["src"])
    whole = scan(client, headers, session_id)

    assert tools_run(db_app, before) == []
    assert [f["path"] for f in findings(client, headers, part["agent_run_id"])] == ["src/app.py"]
    assert findings(client, headers, whole["agent_run_id"]) == findings(
        client, headers, first["agent_run_id"]
    )


def test_a_change_inside_the_paths_reads_only_that_file(client, db_app, code_dir):
    headers, session_id, read = ready(client, db_app, code_dir)
    scan(client, headers, session_id)
    read.clear()

    send_code(client, headers, session_id, {**CODE, "src/util.py": b"x = 2\n"})
    part = scan(client, headers, session_id, paths=["src"])
    whole = scan(client, headers, session_id)

    assert read == {"SEMGREP": ["src/util.py"], "GITLEAKS": ["src/util.py"]}  # once
    assert part["counts"]["HIGH"] == 1
    assert [f["path"] for f in findings(client, headers, whole["agent_run_id"])] == [
        "requirements.txt",
        "settings.py",
        "src/app.py",
    ]


def test_a_failed_tool_keeps_its_earlier_findings_on_a_changed_file(client, db_app, code_dir):
    headers, session_id, _ = ready(client, db_app, code_dir)
    scan(client, headers, session_id, tools=["SEMGREP", "GITLEAKS"])
    mcp = db_app.state.parts["mcp"]
    mcp.outputs[ToolName.GITLEAKS] = lambda job: (_ for _ in ()).throw(ConnectionError())

    send_code(client, headers, session_id, {**CODE, "settings.py": b"API_KEY = 'x'\nY = 1\n"})
    failed = scan(client, headers, session_id, tools=["SEMGREP", "GITLEAKS"])

    assert failed["agent_runs_status"] == "COMPLETED"
    assert failed["notes"] == ["GITLEAKS FAILED"]
    # Nothing read settings.py as it is now: its leak is not shown as fixed.
    assert [(f["path"], f["tools"]) for f in findings(client, headers, failed["agent_run_id"])] == [
        ("settings.py", ["GITLEAKS"]),
        ("src/app.py", ["SEMGREP"]),
    ]


def test_without_gitleaks_the_ai_review_gets_no_code(client, db_app, code_dir):
    """No gitleaks run read the files, so a secret the masker has no pattern for would
    not be [MASKED]: the review gets the finding without its code."""
    headers, session_id, _ = ready(client, db_app, code_dir)
    model = db_app.state.parts["review_model"]

    scan(client, headers, session_id, tools=["SEMGREP"], analyze=True)

    assert model.prompts
    assert "Code: not available" in model.sent_text()
    assert "os.system(input())" not in model.sent_text()


def test_the_auto_scope_runs_only_the_code_scans_own_calls(client, db_app, code_dir):
    """No person approved the session's own scope, so it takes no other action: not one
    with options (they could send the code away), not even a bare one."""
    headers, session_id, _ = ready(client, db_app, code_dir)
    done = scan(client, headers, session_id, tools=["SONAR_SCAN"])
    before = len(db_app.state.parts["mcp"].jobs)
    target = f"/workspace/code/{session_id}"

    # (The real risk check also rates sonar.host.url HIGH: risk_ops.json, tested in services/ai.)
    for arguments in (["-Dsonar.host.url=https://attacker.example"], []):
        sent = client.post(
            f"/assessments/{done['assessment_id']}/actions",
            json={"tool": "SONAR_SCAN", "target": target, "arguments": arguments},
            headers=headers,
        )
        assert sent.status_code == 422, sent.json()
        assert sent.json()["details"]["reason"] == "CODE_SCAN_ONLY"

    assert tools_run(db_app, before) == []
    blocked = [e for e in db_app.state.parts["audit"].events if e.event_type == "ACTION_BLOCKED"]
    assert [e.details["reason"] for e in blocked] == ["CODE_SCAN_ONLY", "CODE_SCAN_ONLY"]


def test_sonar_scan_reads_a_folder_named_after_the_session(client, db_app, code_dir):
    """sonar_scan names the SonarQube project after its folder: one project per session."""
    headers, session_id, _ = ready(client, db_app, code_dir)
    scan(client, headers, session_id, tools=["SONAR_SCAN"])
    (job,) = [job for job in db_app.state.parts["mcp"].jobs if job.tool == "SONAR_SCAN"]
    assert job.target.endswith(f"/reconix-{UUID(session_id).hex}")


# ---------------------------------------------------------------------------
# Logs and restarts
# ---------------------------------------------------------------------------


def test_a_tool_log_is_served_masked_as_text(client, db_app, code_dir):
    headers, session_id, _ = ready(client, db_app, code_dir)
    done = scan(client, headers, session_id)

    log = client.get(f"/code-scans/{done['agent_run_id']}/logs/sonar_scan", headers=headers)
    upper = client.get(f"/code-scans/{done['agent_run_id']}/logs/SONAR_SCAN", headers=headers)
    missing = client.get(f"/code-scans/{done['agent_run_id']}/logs/nmap", headers=headers)

    assert log.status_code == 200
    assert log.headers["content-type"].startswith("text/plain")
    assert log.text == SONAR_LOG == upper.text
    assert missing.status_code == 404
    assert missing.json()["code"] == "TOOL_LOG_NOT_FOUND"


def test_a_restart_ends_a_running_scan_and_removes_its_copy(
    client, db_app, code_dir, session_factory
):
    headers, session_id, _ = ready(client, db_app, code_dir)
    slow_tools(db_app, 0.3)
    started = client.post(f"/sessions/{session_id}/code-scans", json={}, headers=headers)
    scan_id = started.json()["agent_run_id"]
    time.sleep(0.1)  # semgrep is running on the copy
    assert list((code_dir / session_id).glob("_reconix_scan_*"))

    with session_factory() as db:
        code_scans.recover_interrupted(db, str(code_dir))

    ended = client.get(f"/code-scans/{scan_id}", headers=headers).json()
    assert (ended["agent_runs_status"], ended["error"]) == ("FAILED", "INTERRUPTED")
    assert not list((code_dir / session_id).glob("_reconix_scan_*"))
    time.sleep(0.5)  # the running call ends; the scan keeps its FAILED end
    assert client.get(f"/code-scans/{scan_id}", headers=headers).json()["error"] == "INTERRUPTED"
