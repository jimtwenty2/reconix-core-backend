"""Code fixes: scan -> fix -> live events -> result, plus cancel, errors and ownership.

Through the API and a real database, with the fake Kali MCP (its SEMGREP reads the copy
folder on disk, so a fixed file is no longer reported) and a scripted fake model (no real
model call). The fix runs in the background, so one TestClient stays open.
"""

import asyncio
import hashlib
import json
import time
from pathlib import Path

import pytest

from reconix_ai.providers import ProviderError, ToolCall, ToolReply
from reconix_api.services import code_fixes
from tests.integration.test_code_scan_flow import event_types, send_code, vscode_session
from tests.integration.test_session_code_scan_flow import (
    APP_PY,
    CODE,
    findings,
    kali_tools,
    scan,
)

FIXED_LINE = "print(input())  # eval-me"


@pytest.fixture
def client(code_client):
    return code_client


def scripted(monkeypatch, *steps: tuple[str, dict]) -> list[list[dict]]:
    """The fix agent's model answers with these tool calls, one per step."""
    seen: list[list[dict]] = []

    async def fake(messages, tools, config, on_piece=None, on_thinking=None):
        seen.append(messages)
        name, args = steps[min(len(seen), len(steps)) - 1]
        if on_thinking:
            await on_thinking("Reading the call. ")
        if on_piece:
            await on_piece("Replacing os.system.")
        call = ToolCall(f"c{len(seen)}", name, json.dumps(args))
        return ToolReply("", [call], prompt_tokens=100, completion_tokens=10, masked_count=0)

    monkeypatch.setattr(code_fixes, "complete_with_tools", fake)
    return seen


def fix_steps() -> tuple[tuple[str, dict], ...]:
    return (
        ("read_file", {}),
        ("edit_file", {"old_text": "os.system(input())  # eval-me", "new_text": FIXED_LINE}),
        ("check_fixes", {}),
        ("finish", {"summary": "Printed the input instead of running it."}),
    )


def scanned(client, db_app, code_dir) -> tuple[dict, str, dict[str, dict]]:
    """A vscode session whose code was scanned. Returns headers, session id and the
    findings by path."""
    kali_tools(db_app, code_dir)
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, CODE)
    done = scan(client, headers, session_id, analyze=False)
    assert done["agent_runs_status"] == "COMPLETED", done
    by_path = {f["path"]: f for f in findings(client, headers, done["agent_run_id"])}
    return headers, session_id, by_path


def start(client, headers, session_id, ids: list[str]):
    return client.post(
        f"/sessions/{session_id}/code-fixes", json={"finding_ids": ids}, headers=headers
    )


def wait_for_end(client, headers, fix_id: str) -> dict:
    for _ in range(300):
        fix = client.get(f"/code-fixes/{fix_id}", headers=headers).json()
        if fix["agent_runs_status"] != "RUNNING":
            return fix
        time.sleep(0.02)
    raise AssertionError("the fix did not end")


def read_events(client, headers, fix_id: str, after: int = 0) -> list[tuple[str, dict]]:
    """Every SSE message until FIX_ENDED, as (event, data)."""
    got: list[tuple[str, dict]] = []
    url = f"/code-fixes/{fix_id}/events?after={after}"
    with client.stream("GET", url, headers=headers) as response:
        assert response.status_code == 200
        event = None
        for line in response.iter_lines():
            if line.startswith("event: "):
                event = line.removeprefix("event: ")
            elif line.startswith("data: "):
                got.append((event, json.loads(line.removeprefix("data: "))))
                if event == "FIX_ENDED":
                    break
    return got


def test_a_fix_streams_its_work_and_returns_line_edits(client, db_app, code_dir, monkeypatch):
    headers, session_id, by_path = scanned(client, db_app, code_dir)
    sqli, leak = by_path["src/app.py"], by_path["settings.py"]
    findings_before = client.get(
        f"/findings?assessment_id={sqli['assessment_id']}", headers=headers
    ).json()
    seen = scripted(monkeypatch, *fix_steps())

    started = start(client, headers, session_id, [sqli["finding_id"], leak["finding_id"]])
    assert started.status_code == 202, started.json()
    fix_id = started.json()["agent_run_id"]

    events = read_events(client, headers, fix_id)
    fix = wait_for_end(client, headers, fix_id)
    assert fix["agent_runs_status"] == "COMPLETED", fix
    assert fix["finding_count"] == 2 and fix["error"] is None
    result = fix["result"]
    assert result["files"] == [
        {
            "path": "src/app.py",
            "file_sha256": hashlib.sha256(APP_PY).hexdigest(),
            "edits": [{"start_line": 2, "end_line": 2, "replacement": FIXED_LINE}],
        }
    ]
    outcomes = {item["finding_id"]: item for item in result["results"]}
    assert outcomes[sqli["finding_id"]]["status"] == "FIXED"
    assert outcomes[leak["finding_id"]]["status"] == "NOT_FIXED"
    assert "rotate" in outcomes[leak["finding_id"]]["note"]
    assert "Printed the input" in result["summary"]

    # The live transcript, in order, ending with FIX_ENDED.
    assert events[-1] == ("FIX_ENDED", {"agent_run_id": fix_id, "agent_runs_status": "COMPLETED"})
    lines = [(data["file"], data["kind"], data["text"]) for _, data in events[:-1]]
    assert [data["seq"] for _, data in events[:-1]] == list(range(1, len(lines) + 1))
    assert ("src/app.py", "START", "1 finding") in lines
    assert ("src/app.py", "TOOL", "Edit src/app.py") in lines
    assert ("src/app.py", "RESULT", "+1 −1 lines") in lines
    assert ("src/app.py", "RESULT", "1 no longer reported") in lines
    assert (None, "STATUS", "Checking all changes with the scanners") in lines
    assert ("src/app.py", "DONE", "Finished 1 of 1 files") in lines
    assert {kind for _, kind, _ in lines} >= {"THINKING", "TEXT"}
    # A reconnect after seq 3 gets only the later events.
    again = read_events(client, headers, fix_id, after=3)
    assert again[0][1]["seq"] == 4 and again[-1][0] == "FIX_ENDED"

    # The model never saw the leaked line, and only the app file was sent.
    sent = json.dumps(seen)
    assert "not-a-real-key" not in sent and "settings.py" not in sent
    # Nothing changed on disk, no copy is left, and the rechecks saved no findings.
    folder = code_dir / session_id
    assert (folder / "src/app.py").read_bytes() == APP_PY
    assert not list(folder.glob("_reconix_scan_*"))
    findings_after = client.get(
        f"/findings?assessment_id={sqli['assessment_id']}", headers=headers
    ).json()
    assert len(findings_after) == len(findings_before)
    # One start line and one end line, with counts only.
    audit = [e for e in db_app.state.parts["audit"].events if e.details.get("task") == "CODE_FIX"]
    assert [e.event_type for e in audit] == ["AGENT_RUN_COMPLETED"]
    assert audit[0].details["fixed"] == "1" and audit[0].details["not_fixed"] == "1"
    assert "CODE_FIX_STARTED" in event_types(db_app)
    assert FIXED_LINE not in json.dumps([e.details for e in db_app.state.parts["audit"].events])


def test_a_change_the_scanner_still_reports_is_still_reported(
    client, db_app, code_dir, monkeypatch
):
    headers, session_id, by_path = scanned(client, db_app, code_dir)
    still = "os.system(input().strip())  # eval-me"
    scripted(
        monkeypatch,
        ("edit_file", {"old_text": "os.system(input())  # eval-me", "new_text": still}),
        ("finish", {"summary": "Stripped the input."}),
    )
    fix_id = start(client, headers, session_id, [by_path["src/app.py"]["finding_id"]]).json()
    fix = wait_for_end(client, headers, fix_id["agent_run_id"])
    assert fix["result"]["results"][0]["status"] == "STILL_REPORTED"


def test_refusals(client, db_app, code_dir, monkeypatch):
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, CODE)
    some_id = "00000000-0000-0000-0000-000000000001"
    no_scan = start(client, headers, session_id, [some_id])
    assert (no_scan.status_code, no_scan.json()["code"]) == (409, "NO_FINISHED_SCAN")

    headers, session_id, by_path = scanned(client, db_app, code_dir)
    unknown = start(client, headers, session_id, [some_id])
    assert (unknown.status_code, unknown.json()["code"]) == (422, "FINDING_NOT_IN_SCAN")
    assert unknown.json()["details"]["finding_ids"] == [some_id]
    empty = start(client, headers, session_id, [])
    assert empty.status_code == 422

    scripted(monkeypatch, *fix_steps())
    fix_id = start(client, headers, session_id, [by_path["src/app.py"]["finding_id"]]).json()[
        "agent_run_id"
    ]
    wait_for_end(client, headers, fix_id)
    other_headers, other_session = vscode_session(client)
    for response in (
        start(client, other_headers, session_id, [by_path["src/app.py"]["finding_id"]]),
        client.get(f"/code-fixes/{fix_id}", headers=other_headers),
        client.get(f"/code-fixes/{fix_id}/events", headers=other_headers),
        client.post(f"/code-fixes/{fix_id}/cancel", headers=other_headers),
    ):
        assert (response.status_code, response.json()["code"]) == (403, "NOT_YOUR_SESSION")
    missing = client.get(f"/code-fixes/{by_path['src/app.py']['finding_id']}", headers=headers)
    assert (missing.status_code, missing.json()["code"]) == (404, "CODE_FIX_NOT_FOUND")
    ended = client.post(f"/code-fixes/{fix_id}/cancel", headers=headers)
    assert (ended.status_code, ended.json()["code"]) == (409, "FIX_ENDED")


def test_cancel_stops_a_running_fix(client, db_app, code_dir, monkeypatch):
    headers, session_id, by_path = scanned(client, db_app, code_dir)
    calls = []

    async def never_answers(messages, tools, config, on_piece=None, on_thinking=None):
        calls.append(1)
        await asyncio.sleep(3600)

    monkeypatch.setattr(code_fixes, "complete_with_tools", never_answers)
    finding_id = by_path["src/app.py"]["finding_id"]
    fix_id = start(client, headers, session_id, [finding_id]).json()["agent_run_id"]
    for _ in range(200):
        if calls:
            break
        time.sleep(0.01)
    busy = start(client, headers, session_id, [finding_id])
    assert (busy.status_code, busy.json()["code"]) == (409, "FIX_RUNNING")
    no_scan = client.post(f"/sessions/{session_id}/code-scans", json={}, headers=headers)
    assert (no_scan.status_code, no_scan.json()["code"]) == (409, "FIX_RUNNING")

    cancelled = client.post(f"/code-fixes/{fix_id}/cancel", headers=headers)
    assert cancelled.status_code == 200, cancelled.json()
    assert (
        cancelled.json()["agent_runs_status"] == "CANCELLED" and cancelled.json()["result"] is None
    )
    events = read_events(client, headers, fix_id)
    assert events[-1] == ("FIX_ENDED", {"agent_run_id": fix_id, "agent_runs_status": "CANCELLED"})
    assert "AGENT_RUN_CANCELLED" in event_types(db_app)
    # Its agents stopped: a new fix may start.
    scripted(monkeypatch, *fix_steps())
    for _ in range(100):
        again = start(client, headers, session_id, [finding_id])
        if again.status_code == 202:
            break
        time.sleep(0.02)
    assert again.status_code == 202, again.json()
    wait_for_end(client, headers, again.json()["agent_run_id"])


def test_a_model_error_fails_the_fix_with_its_code(client, db_app, code_dir, monkeypatch):
    headers, session_id, by_path = scanned(client, db_app, code_dir)

    async def model_down(messages, tools, config, on_piece=None, on_thinking=None):
        raise ProviderError("MODEL_UNAVAILABLE", "The model could not answer.")

    monkeypatch.setattr(code_fixes, "complete_with_tools", model_down)
    fix_id = start(client, headers, session_id, [by_path["src/app.py"]["finding_id"]]).json()
    fix = wait_for_end(client, headers, fix_id["agent_run_id"])
    assert (fix["agent_runs_status"], fix["error"], fix["result"]) == (
        "FAILED",
        "MODEL_UNAVAILABLE",
        None,
    )
    assert "AGENT_RUN_FAILED" in event_types(db_app)


def test_a_file_changed_since_the_scan_is_not_sent(client, db_app, code_dir, monkeypatch):
    headers, session_id, by_path = scanned(client, db_app, code_dir)
    seen = scripted(monkeypatch, *fix_steps())
    Path(code_dir / session_id / "src/app.py").write_bytes(APP_PY + b"# edited\n")
    fix_id = start(client, headers, session_id, [by_path["src/app.py"]["finding_id"]]).json()
    fix = wait_for_end(client, headers, fix_id["agent_run_id"])
    outcome = fix["result"]["results"][0]
    assert outcome["status"] == "NOT_FIXED" and "changed since the last scan" in outcome["note"]
    assert seen == [] and fix["result"]["files"] == []


def test_code_no_gitleaks_run_read_is_not_sent(client, db_app, code_dir, monkeypatch):
    kali_tools(db_app, code_dir)
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, CODE)
    done = scan(client, headers, session_id, analyze=False, tools=["SEMGREP"])
    sqli = next(
        f for f in findings(client, headers, done["agent_run_id"]) if f["path"] == "src/app.py"
    )
    seen = scripted(monkeypatch, *fix_steps())
    fix_id = start(client, headers, session_id, [sqli["finding_id"]]).json()["agent_run_id"]
    fix = wait_for_end(client, headers, fix_id)
    outcome = fix["result"]["results"][0]
    assert outcome["status"] == "NOT_FIXED" and "GITLEAKS" in outcome["note"]
    assert seen == []
