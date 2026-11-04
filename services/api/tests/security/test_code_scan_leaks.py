"""The leak test for the code scan: secrets in the code and the clone token stay hidden.

Fake secrets sit in the source code itself: one on the line semgrep reports (so it is in
the snippet and in semgrep's own output) and one in a file gitleaks reports. The code
comes in by upload, or by a git clone with a fake GitHub token. Then a code scan with
the AI review runs and its findings are read. Not one canary may show up in the
database, plan.reviews, the logs, the audit log, the prompts to the AI or the API's
answers. The masking and the audit log are the real ones; the agent, MCP, git remote
and AI model are fakes.
"""

import base64
import json
import logging
import subprocess
import time
from pathlib import Path

from sqlalchemy import select

from reconix_api.core.interfaces import ToolName
from reconix_api.core.wiring import build_mask_secrets
from reconix_api.models import AgentRun
from reconix_api.services import code
from tests.integration.test_code_scan_flow import code_assessment, entries, tar_gz
from tests.security.test_no_secret_leaks import (
    Recorder,
    audit_file,  # noqa: F401  (a fixture)
    database_text,
    leaks,
)

# Obvious fakes; "gitleaks:allow" tells the commit hook's secret scan they are on purpose.
LINE_PASSWORD = "LeakCanary-Code-Passw0rd-5521"  # noqa: S105  # gitleaks:allow
FILE_TOKEN = "ghp_LEAKCANARYCODE00000000000000000000000"  # noqa: S105  # gitleaks:allow
CLONE_TOKEN = "ghp_LEAKCANARYCLONE0000000000000000000000"  # noqa: S105  # gitleaks:allow
CANARIES = [LINE_PASSWORD, FILE_TOKEN]
# git sends the clone token as HTTP basic auth, so look for that form too.
CLONE_CANARIES = [
    *CANARIES,
    CLONE_TOKEN,
    base64.b64encode(f"x-access-token:{CLONE_TOKEN}".encode()).decode(),
]

APP_JS = f'const password = "{LINE_PASSWORD}"; eval(req.query.code);\n'.encode()
SETTINGS_JS = f'module.exports = {{ token: "{FILE_TOKEN}" }};\n'.encode()
CODE = {"src/app.js": APP_JS, "config/settings.js": SETTINGS_JS}


def tool_outputs(db_app) -> None:
    """Raw tool output, as leaky as the real tools: semgrep repeats the line it matched.
    Paths are under the job's target (the scan's copy folder), as Kali gives them."""
    mcp = db_app.state.parts["mcp"]
    mcp.outputs[ToolName.SEMGREP] = lambda job: json.dumps(
        {
            "results": [
                {
                    "check_id": "javascript.lang.security.audit.eval-detected",
                    "path": f"{job.target}/src/app.js",
                    "start": {"line": 1, "col": 49},
                    "end": {"line": 1, "col": 70},
                    "extra": {
                        "severity": "ERROR",
                        "message": "eval() with user input.",
                        "lines": APP_JS.decode().strip(),
                    },
                }
            ]
        }
    )
    mcp.outputs[ToolName.GITLEAKS] = lambda job: json.dumps(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub personal access token",
                "File": f"{job.target}/config/settings.js",
                "StartLine": 1,
                "EndLine": 1,
                "Secret": FILE_TOKEN,
                "Match": f'token: "{FILE_TOKEN}"',
                "Line": SETTINGS_JS.decode().strip(),
            }
        ]
    )


def run_the_code_flow(client, db_app) -> Recorder:
    session = client.post("/sessions", json={"interface": "vscode"}).json()
    api = Recorder(client, {"Authorization": f"Bearer {session['token']}"})
    session_id = session["session_id"]

    synced = api.call(
        "POST", f"/sessions/{session_id}/code/sync", json={"files": entries(CODE)}
    ).json()
    uploaded = client.put(  # the body is gzip, so it needs its own Content-Type
        f"/sessions/{session_id}/code",
        content=tar_gz(CODE),
        headers={**api.headers, "Content-Type": "application/gzip"},
    )
    api.answers.append(uploaded.text)
    assert uploaded.status_code == 200, uploaded.text
    tool_outputs(db_app)

    assessment_id = code_assessment(client, api.headers, synced["target"])
    started = api.call(
        "POST", f"/assessments/{assessment_id}/code-scans", json={"analyze": True}
    ).json()
    scan_findings(api, started["agent_run_id"])
    api.call("GET", f"/assessments/{assessment_id}/actions")
    return api


def scan_findings(api: Recorder, scan_id: str) -> None:
    for _ in range(200):
        scan = api.call("GET", f"/code-scans/{scan_id}").json()
        if scan["agent_runs_status"] != "RUNNING":
            break
        time.sleep(0.02)
    assert scan["agent_runs_status"] == "COMPLETED", scan
    found = api.call("GET", f"/code-scans/{scan_id}/findings").json()
    assert len(found) == 2, "both tools should give a finding"


def test_no_secret_from_the_uploaded_code_leaks(
    code_client,
    db_app,
    session_factory,
    audit_file,  # noqa: F811
    caplog,
):
    caplog.set_level(logging.DEBUG)
    db_app.state.mask_secrets = build_mask_secrets()

    api = run_the_code_flow(code_client, db_app)

    places = {
        "the database": database_text(session_factory),
        "the logs": caplog.text,
        "the audit log": audit_file.read_text(),
        "the requests to the AI": repr(db_app.state.parts["agent"].requests)
        + db_app.state.parts["review_model"].sent_text(),
        "the API answers": "\n".join(api.answers),
    }
    assert leaks(places, CANARIES) == []
    assert db_app.state.parts["review_model"].prompts, "the AI review should have run"
    assert "[MASKED" in "\n".join(api.answers), "the masking should have run"


def git_remote(folder: Path) -> Path:
    """A local git repo holding the leaky code, in place of the GitHub repo."""
    for path, data in CODE.items():
        (folder / path).parent.mkdir(parents=True, exist_ok=True)
        (folder / path).write_bytes(data)
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(folder)}
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(folder)]
    for args in (["init", "-q"], ["add", "."], ["commit", "-qm", "one"]):
        subprocess.run([*git, *args], check=True, env=env)  # noqa: S603
    return folder


def reviews_text(session_factory) -> str:
    with session_factory() as db:
        reviews = db.scalars(select(AgentRun.plan["reviews"]).where(AgentRun.plan.isnot(None)))
        return json.dumps([review for review in reviews if review])


def test_no_secret_or_clone_token_leaks_from_a_cloned_repo(
    code_client,
    db_app,
    session_factory,
    tmp_path,
    monkeypatch,
    audit_file,  # noqa: F811
    caplog,
):
    caplog.set_level(logging.DEBUG)
    db_app.state.mask_secrets = build_mask_secrets()
    remote = git_remote(tmp_path / "remote")
    monkeypatch.setattr(code, "clone_source", lambda _: ("file", f"file://{remote}"))
    tool_outputs(db_app)
    session = code_client.post("/sessions", json={"interface": "vscode"}).json()
    api = Recorder(code_client, {"Authorization": f"Bearer {session['token']}"})
    session_id = session["session_id"]

    cloned = api.call(
        "POST",
        f"/sessions/{session_id}/code/clone",
        json={"url": "https://github.com/DansPK/vuln-lab", "token": CLONE_TOKEN},
    )
    assert cloned.status_code == 200, cloned.text
    started = api.call(
        "POST",
        f"/sessions/{session_id}/code-scans",
        json={"tools": ["SEMGREP", "GITLEAKS"], "analyze": True},
    )
    assert started.status_code == 202, started.text
    scan_findings(api, started.json()["agent_run_id"])

    places = {
        "the database": database_text(session_factory),
        "plan.reviews": reviews_text(session_factory),
        "the logs": caplog.text,
        "the audit log": audit_file.read_text(),
        "the prompts to the AI": db_app.state.parts["review_model"].sent_text(),
        "the API answers": "\n".join(api.answers),
    }
    assert leaks(places, CLONE_CANARIES) == []
    assert db_app.state.parts["review_model"].prompts, "the AI review should have run"
    assert places["plan.reviews"] != "[]", "the reviews should be stored"
    assert "CODE_CLONED" in places["the audit log"], "the clone should be audited"
