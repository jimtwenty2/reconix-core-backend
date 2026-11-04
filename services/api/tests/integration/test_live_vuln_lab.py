"""The source code scan against the real Kali container, with DansPK/vuln-lab as the proof.

Clone the public repo (this computer's git, no token), scan 3 of its folders with all 7
tools, check what the tools found, copy the same tree in as a local folder and get the
same findings, then rescan with no change and make no Kali call. The harness check, the
masking, the audit log and call_tool (make_call_tool) are the real ones; the AI review's
model is the fake one (integration conftest).

Opt-in. Besides RECONIX_TEST_DATABASE_URL, set:

    RECONIX_TEST_MCP_URL=http://127.0.0.1:8096/mcp
    RECONIX_TEST_MCP_ACCESS_KEY=<RECONIX_MCP_ACCESS_KEY from .env>
    RECONIX_TEST_CODE_DIR=<absolute path of data/code, the folder Kali mounts at /workspace/code>

The test writes its sessions' code into RECONIX_TEST_CODE_DIR and removes it at the end.
It needs internet (git clone; Kali downloads the trivy and grype databases) and takes a few
minutes: sonar_scan starts SonarQube on its first call.
sonar_scan needs Kali's SonarQube server up: on a small Docker VM (about 4 GB) the kernel
can kill it during the other tools; then restart the Kali container (its bootstrap starts it).
"""

import dataclasses
import os
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from reconix_api.core.config import get_settings
from reconix_api.core.wiring import build_interfaces, build_mask_secrets
from tests.integration.test_code_scan_flow import vscode_session

MCP_URL = os.environ.get("RECONIX_TEST_MCP_URL", "")
MCP_ACCESS_KEY = os.environ.get("RECONIX_TEST_MCP_ACCESS_KEY", "")
CODE_DIR = os.environ.get("RECONIX_TEST_CODE_DIR", "")

pytestmark = pytest.mark.skipif(
    not (MCP_URL and MCP_ACCESS_KEY and CODE_DIR),
    reason="RECONIX_TEST_MCP_URL, RECONIX_TEST_MCP_ACCESS_KEY or RECONIX_TEST_CODE_DIR is not set",
)

URL = "https://github.com/DansPK/vuln-lab"
PATHS = ["api", "juice-shop-src/lib", "source-code/vulpy/bad"]  # api is VAmPI
ALL_TOOLS = ["SEMGREP", "GITLEAKS", "TRIVY", "GRYPE", "OSV_SCANNER", "SYFT", "SONAR_SCAN"]
DEPENDENCY_TOOLS = {"TRIVY", "GRYPE", "OSV_SCANNER"}
SCAN_MINUTES = 15
# From the live run on 2026-11-04 (vuln-lab HEAD, semgrep 1.183.0 p/default, gitleaks 8.26.0,
# trivy 0.66.0, grype 0.120.1, osv-scanner 2.7.0, syft 1.51.0).
# shortcut: the dependency counts follow the advisory databases and vuln-lab's HEAD, so they
# move over time; update them from the -s output when they do.
FINDINGS_PER_TOOL = {"SEMGREP": 41, "GITLEAKS": 2, "TRIVY": 15, "GRYPE": 15, "OSV_SCANNER": 56}
SYFT_PACKAGES = 11


@dataclasses.dataclass
class Kali:
    client: TestClient
    tools_called: list[str]  # every call_tool, tools_info included
    sessions: list[str]  # their code folders are removed at the end


@pytest.fixture
def kali(db_app, tmp_path):
    real = build_interfaces(
        audit_log_path=str(tmp_path / "audit.jsonl"), mcp_url=MCP_URL, mcp_access_key=MCP_ACCESS_KEY
    )
    tools_called: list[str] = []

    async def call_tool(job):
        tools_called.append(str(job.tool))
        return await real.call_tool(job)

    db_app.state.interfaces = dataclasses.replace(
        db_app.state.interfaces, check=real.check, write_audit=real.write_audit, call_tool=call_tool
    )
    db_app.state.mask_secrets = build_mask_secrets()
    settings = db_app.dependency_overrides[get_settings]()
    # No local clone: the test takes the git clone path with this computer's credentials.
    changed = settings.model_copy(update={"code_dir": CODE_DIR, "local_repo_roots": []})
    db_app.dependency_overrides[get_settings] = lambda: changed

    sessions: list[str] = []
    with TestClient(db_app, base_url="http://127.0.0.1/api/v1") as client:
        try:
            yield Kali(client, tools_called, sessions)
        finally:
            for session_id in sessions:
                shutil.rmtree(Path(CODE_DIR) / session_id, ignore_errors=True)


def new_session(kali: Kali) -> tuple[dict, str]:
    headers, session_id = vscode_session(kali.client)
    kali.sessions.append(session_id)
    return headers, session_id


def scan(kali: Kali, headers: dict, session_id: str) -> tuple[dict, list[dict]]:
    """Runs a code scan of PATHS with all 7 tools; returns the ended scan and its findings."""
    started = kali.client.post(
        f"/sessions/{session_id}/code-scans",
        json={"paths": PATHS, "tools": ALL_TOOLS, "analyze": True},
        headers=headers,
    )
    assert started.status_code == 202, started.json()
    scan_id = started.json()["agent_run_id"]
    deadline = time.monotonic() + SCAN_MINUTES * 60
    while time.monotonic() < deadline:
        ended = kali.client.get(f"/code-scans/{scan_id}", headers=headers).json()
        if ended["agent_runs_status"] != "RUNNING":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"the scan did not end in {SCAN_MINUTES} minutes")
    found = kali.client.get(f"/code-scans/{scan_id}/findings", headers=headers).json()
    report(ended, found)
    return ended, found


def report(ended: dict, found: list[dict]) -> None:
    """Printed with -s, so the exact counts can be pinned after a run."""
    print(f"\n=== {ended['agent_runs_status']} error={ended['error']} notes={ended['notes']}")
    print(f"    counts={ended['counts']}")
    for tool in ALL_TOOLS:
        print(f"    {tool}: {sum(tool in f['tools'] for f in found)} findings")


def same(found: list[dict]) -> set[tuple]:
    """What a finding is, without the ids and paths that differ per session."""
    return {
        (tuple(f["tools"]), f["rule_id"], f["path"], f["line"], f["severity_status"]) for f in found
    }


def found_by(found: list[dict], tool: str, path: str) -> list[dict]:
    return [f for f in found if tool in f["tools"] and f["path"] == path]


def assert_every_tool_ran(kali: Kali, headers: dict, ended: dict) -> None:
    """Each tool has a COMPLETED tool run, or a note that says why not."""
    actions = kali.client.get(f"/assessments/{ended['assessment_id']}/actions", headers=headers)
    completed = {
        action["tool"].upper()
        for action in actions.json()
        if any(run["tool_run_status"] == "COMPLETED" for run in action["tool_runs"])
    }
    for tool in ALL_TOOLS:
        notes = [note for note in ended["notes"] if note.startswith(tool)]
        assert tool in completed or notes, f"{tool} did not run and has no note"


def assert_vuln_lab_findings(found: list[dict], ended: dict) -> None:
    bad = "source-code/vulpy/bad"
    sql = [
        f
        for f in found_by(found, "SEMGREP", f"{bad}/libuser.py")
        if "CWE-89" in " ".join(f["cwe_ids"]) or "sql" in (f["rule_id"] or "").lower()
    ]
    assert sql, "semgrep found no SQL injection in libuser.py"
    secret = found_by(found, "SEMGREP", f"{bad}/vulpy.py")
    assert any("secret" in (f["rule_id"] or "").lower() for f in secret)
    assert any("debug" in (f["rule_id"] or "").lower() for f in found if "SEMGREP" in f["tools"])
    # The `{{ post.text | safe }}` XSS (line 23) has no rule in p/default, Kali's semgrep
    # default: only r/python.flask's template-unescaped-with-safe finds it (checked live).
    # So this only proves the templates are scanned (django-no-csrf-token, line 13).
    assert found_by(found, "SEMGREP", f"{bad}/templates/posts.view.html")

    keys = [
        f
        for f in found_by(found, "GITLEAKS", "juice-shop-src/lib/insecurity.ts")
        if "private-key" in (f["rule_id"] or "")
    ]
    assert keys, "gitleaks found no private key in insecurity.ts"
    assert all(f["severity_status"] == "HIGH" and f["snippet"] is None for f in keys)

    manifest = [
        f
        for f in found
        if DEPENDENCY_TOOLS & set(f["tools"]) and f["path"] == "api/requirements.txt"
    ]
    assert manifest, "no dependency tool found anything in api/requirements.txt"

    per_tool = {tool: sum(tool in f["tools"] for f in found) for tool in FINDINGS_PER_TOOL}
    assert per_tool == FINDINGS_PER_TOOL
    assert f"SYFT {SYFT_PACKAGES} packages" in ended["notes"], ended["notes"]
    assert any(note.startswith("SONAR_SCAN OK") for note in ended["notes"]), ended["notes"]

    for finding in found:
        path = finding["path"] or ""
        assert any(path.startswith(f"{folder}/") for folder in PATHS), finding


def test_vuln_lab_scan_finds_the_known_problems(kali, tmp_path):
    headers, session_id = new_session(kali)
    cloned = kali.client.post(
        f"/sessions/{session_id}/code/clone", json={"url": URL}, headers=headers
    )
    assert cloned.status_code == 200, cloned.json()
    assert cloned.json()["source"] == "GITHUB"

    ended, found = scan(kali, headers, session_id)

    assert ended["agent_runs_status"] == "COMPLETED", ended
    assert_every_tool_ran(kali, headers, ended)
    assert_vuln_lab_findings(found, ended)
    log = kali.client.get(f"/code-scans/{ended['agent_run_id']}/logs/sonar_scan", headers=headers)
    assert log.status_code == 200 and log.text.strip(), "the sonar_scan log is empty"

    # The same tree, as a local folder (outside the code folder, which copy_folder refuses).
    copy = shutil.copytree(Path(CODE_DIR) / session_id, tmp_path / "vuln-lab")
    copy_headers, copy_session = new_session(kali)
    copied = kali.client.post(
        f"/sessions/{copy_session}/code/folder", json={"path": str(copy)}, headers=copy_headers
    )
    assert copied.status_code == 200, copied.json()
    assert copied.json()["files"] == cloned.json()["files"]
    copy_ended, copy_found = scan(kali, copy_headers, copy_session)
    assert copy_ended["agent_runs_status"] == "COMPLETED", copy_ended
    assert same(copy_found) == same(found)

    # Nothing changed since the first scan: every finding is carried over, Kali is not called.
    calls = len(kali.tools_called)
    again, again_found = scan(kali, headers, session_id)
    assert again["agent_runs_status"] == "COMPLETED", again
    assert kali.tools_called[calls:] == []
    assert same(again_found) == same(found)
