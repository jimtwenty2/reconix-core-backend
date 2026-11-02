"""The leak test for the VS Code code flow: secrets in the uploaded code stay masked.

Fake secrets sit in the source code itself: one on the line semgrep reports (so it is in
the snippet and in semgrep's own output), one in a file gitleaks reports, and one in a
file name. Then the flow runs: sync, upload, path scope, code scan with analysis, scan
findings. Not one canary may show up in the database, the logs, the audit log, the
requests to the AI or the API's answers. The masking and the audit log are the real
ones; the agent and MCP are fakes.
"""

import json
import logging
import time

from reconix_api.core.interfaces import ToolName
from reconix_api.core.wiring import build_mask_secrets
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
CANARIES = [LINE_PASSWORD, FILE_TOKEN]

APP_JS = f'const password = "{LINE_PASSWORD}"; eval(req.query.code);\n'.encode()
SETTINGS_JS = f'module.exports = {{ token: "{FILE_TOKEN}" }};\n'.encode()
CODE = {"src/app.js": APP_JS, "config/settings.js": SETTINGS_JS}


def tool_outputs(db_app, target: str) -> None:
    """Raw tool output, as leaky as the real tools: semgrep repeats the line it matched."""
    mcp = db_app.state.parts["mcp"]
    mcp.outputs[ToolName.SEMGREP] = json.dumps(
        {
            "results": [
                {
                    "check_id": "javascript.lang.security.audit.eval-detected",
                    "path": f"{target}/src/app.js",
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
    mcp.outputs[ToolName.GITLEAKS] = json.dumps(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub personal access token",
                "File": f"{target}/config/settings.js",
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
    tool_outputs(db_app, synced["target"])

    assessment_id = code_assessment(client, api.headers, synced["target"])
    started = api.call(
        "POST", f"/assessments/{assessment_id}/code-scans", json={"analyze": True}
    ).json()
    for _ in range(200):
        scan = api.call("GET", f"/code-scans/{started['agent_run_id']}").json()
        if scan["agent_runs_status"] != "RUNNING":
            break
        time.sleep(0.02)
    assert scan["agent_runs_status"] == "COMPLETED", scan
    found = api.call("GET", f"/code-scans/{started['agent_run_id']}/findings").json()
    assert len(found) == 2, "both tools should give a finding"
    api.call("GET", f"/agent-runs/{scan['analysis_run_id']}")
    api.call("GET", f"/assessments/{assessment_id}/actions")
    return api


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
        "the requests to the AI": repr(db_app.state.parts["agent"].requests),
        "the API answers": "\n".join(api.answers),
    }
    assert leaks(places, CANARIES) == []
    assert "[MASKED" in "\n".join(api.answers), "the masking should have run"
