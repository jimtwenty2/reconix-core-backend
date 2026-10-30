"""The leak test: plant fake secrets, run the flow, and look for them everywhere.

Fake secrets (canaries) go in through a chat message, a blocked action's arguments, the
tool's raw output and an AI provider's API key and address. Then the flow runs: scope,
action, tool run, findings, analysis, report and its 3 files. Not one canary may show up
in the database, the logs, the audit log, the requests to the AI, the API's answers or
the report files, not even in base64. The masking and the audit log are the real ones;
the agent and MCP are fakes.

Needs PostgreSQL (RECONIX_TEST_DATABASE_URL), like the integration tests. Qdrant is not
covered here: knowledge add-ons, the API's writes to it, have their own leak test in
test_knowledge_add_on_leaks.py, and the knowledge loader's masking is tested in
services/ai/tests/unit/knowledge/test_chunks.py. The API logs little today (only
unexpected errors), so the log search mostly guards log lines added later.
"""

import base64
import dataclasses
import io
import logging
import zipfile
from pathlib import Path

import pytest
from pypdf import PdfReader
from sqlalchemy import select, text

from reconix_ai import harness
from reconix_api.core.config import get_settings
from reconix_api.core.interfaces import ToolName
from reconix_api.core.wiring import build_mask_secrets
from reconix_api.models import Base, ToolRun
from tests.integration.test_action_flow import active_assessment

# Obvious fakes. Each is long and unusual, so a hit can only be a leak. "gitleaks:allow"
# tells the commit hook's secret scan they are fakes on purpose.
CHAT_PASSWORD = "LeakCanary-Chat-Passw0rd-4471"  # noqa: S105
ARGUMENT_PASSWORD = "LeakCanary-Arg-Passw0rd-9902"  # noqa: S105  # gitleaks:allow
TOOL_TOKEN = "ghp_LEAKCANARY000000000000000000000000"  # noqa: S105
TOOL_PRIVATE_KEY = "MIIEowIBAAKCAQEAleakcanaryPRIVATEkeyBODY0000"  # gitleaks:allow
PROVIDER_KEY = "sk-test-LEAKCANARY-0000"  # gitleaks:allow
URL_PASSWORD = "LeakCanary-Url-Passw0rd-3318"  # noqa: S105
PEM_BEGIN = "-----BEGIN RSA PRIVATE KEY-----"  # gitleaks:allow
PEM_KEY = f"{PEM_BEGIN}\\n{TOOL_PRIVATE_KEY}\\n-----END RSA PRIVATE KEY-----"
CANARIES = [
    CHAT_PASSWORD,
    ARGUMENT_PASSWORD,
    TOOL_TOKEN,
    TOOL_PRIVATE_KEY,
    PROVIDER_KEY,
    URL_PASSWORD,
]

GITLEAKS_OUTPUT = f"""[
 {{
  "RuleID": "github-pat",
  "Description": "GitHub personal access token",
  "StartLine": 3,
  "Match": "token = \\"{TOOL_TOKEN}\\"",
  "Secret": "{TOOL_TOKEN}",
  "File": "/tmp/testrepo/config/settings.py",
  "Fingerprint": "/tmp/testrepo/config/settings.py:github-pat:3"
 }},
 {{
  "RuleID": "private-key",
  "Description": "Private key",
  "StartLine": 1,
  "Match": "{PEM_KEY}",
  "Secret": "{PEM_KEY}",
  "File": "/tmp/testrepo/deploy/id_rsa",
  "Fingerprint": "/tmp/testrepo/deploy/id_rsa:private-key:1"
 }}
]"""

SCOPE = {
    "max_risk": "HIGH",
    "allowed_tools": ["NMAP", "GITLEAKS"],
    "targets": [{"type": "ip", "value": "172.20.0.5"}],
}


class Recorder:
    """Calls the API like a client would and keeps every answer, to search them later."""

    def __init__(self, client, headers: dict) -> None:
        self.client = client
        self.headers = headers
        self.answers: list[str] = []
        self.sign_in_secrets: list[str] = []  # tokens and codes: fine in answers, nowhere else

    def call(self, method: str, path: str, **kwargs):
        response = self.client.request(method, path, headers=self.headers, **kwargs)
        self.answers.append(response.text)
        return response


@pytest.fixture
def audit_file(db_app, tmp_path) -> Path:
    """The real audit writer (one JSON line per event), in place of the fake."""
    path = tmp_path / "audit.jsonl"
    db_app.state.interfaces = dataclasses.replace(
        db_app.state.interfaces, write_audit=harness.make_audit_writer(str(path))
    )
    return path


@pytest.fixture
def reports_dir(db_app, tmp_path) -> Path:
    settings = db_app.dependency_overrides[get_settings]()
    settings.reports_dir = str(tmp_path / "reports")
    return tmp_path / "reports"


@pytest.fixture
def leak_app(db_app, audit_file, reports_dir):
    """The app with the real masking, the real audit log, and a tool that leaks secrets."""
    db_app.state.mask_secrets = build_mask_secrets()
    db_app.state.parts["mcp"].outputs[ToolName.GITLEAKS] = GITLEAKS_OUTPUT
    return db_app


def run_the_flow(client, leak_app) -> Recorder:
    session = client.post("/sessions", json={"interface": "cli"}).json()
    api = Recorder(client, {"Authorization": f"Bearer {session['token']}"})
    api.answers.append(str(session))

    message = f"use password={CHAT_PASSWORD} for the test login"
    sent = api.call(
        "POST", f"/sessions/{session['session_id']}/messages", json={"content": message}
    )
    assert sent.status_code == 201, sent.text

    assessment_id = active_assessment(client, api.headers, SCOPE)
    # A blocked action is still saved and listed, so a secret pasted into its arguments
    # must be masked there. (This fake check blocks it on scope; the real command check
    # would block it too, since option values must match fixed patterns.)
    blocked = api.call(
        "POST",
        f"/assessments/{assessment_id}/actions",
        json={
            "tool": "GITLEAKS",
            "target": "10.9.9.9",
            "arguments": ["--log-opts", f"password={ARGUMENT_PASSWORD}"],
        },
    )
    assert blocked.status_code == 422, blocked.text
    action = api.call(
        "POST",
        f"/assessments/{assessment_id}/actions",
        json={"tool": "GITLEAKS", "target": "172.20.0.5"},
    )
    assert action.status_code == 201, action.text
    api.call("GET", f"/assessments/{assessment_id}/actions")
    api.call("GET", f"/actions/{blocked.json()['details']['action_id']}")
    found = api.call("GET", "/findings", params={"assessment_id": assessment_id})
    assert found.json(), "the gitleaks output should give findings"
    for finding in found.json():
        api.call("GET", f"/findings/{finding['finding_id']}")

    analysis = api.call("POST", f"/assessments/{assessment_id}/analyze")
    assert analysis.status_code == 201, analysis.text
    report = api.call("POST", f"/assessments/{assessment_id}/reports")
    assert report.status_code == 201, report.text

    provider = api.call(
        "POST",
        "/llm-providers",
        json={
            "provider_type": "OPENAI",
            "display_name": "Leak test",
            "model_name": "gpt-4o",
            "api_key": PROVIDER_KEY,
        },
    )
    assert provider.status_code == 201, provider.text
    api.call("GET", "/llm-providers")
    refused = api.call(
        "POST",
        "/llm-providers",
        json={
            "provider_type": "OPENAI_API_COMPATIBLE",
            "display_name": "Leak test address",
            "model_name": "any",
            "base_url": f"https://admin:{URL_PASSWORD}@llm.example.com/v1",
        },
    )
    assert refused.status_code == 422, refused.text

    code = api.call("POST", "/sessions/web-sign-in-codes").json()["code"]
    web = api.call("POST", "/sessions/web-sign-in", json={"code": code}).json()
    api.sign_in_secrets = [session["token"], code, web["token"]]
    return api


def database_text(session_factory) -> str:
    """Every row of every table, as text."""
    rows = []
    with session_factory() as db:
        for table in Base.metadata.sorted_tables:
            rows += [str(tuple(row)) for row in db.execute(text(f"SELECT * FROM {table.name}"))]  # noqa: S608
    return "\n".join(rows)


def report_text(reports_dir: Path) -> str:
    """The text inside the 3 report files: JSON as is, DOCX from its XML, PDF read back."""
    parts = []
    for path in reports_dir.rglob("report.*"):
        if path.suffix == ".json":
            parts.append(path.read_text())
        elif path.suffix == ".docx":
            with zipfile.ZipFile(path) as docx:
                xml = [name for name in docx.namelist() if name.endswith((".xml", ".rels"))]
                parts += [docx.read(name).decode() for name in xml]
        elif path.suffix == ".pdf":
            reader = PdfReader(io.BytesIO(path.read_bytes()))
            parts += [page.extract_text() for page in reader.pages]
    return "\n".join(parts)


def leaks(places: dict[str, str], canaries: list[str] = CANARIES) -> list[str]:
    """Each place where a canary, or its base64 form, shows up."""
    found = []
    for name, content in places.items():
        for canary in canaries:
            encoded = base64.b64encode(canary.encode()).decode()
            if canary in content or encoded in content:
                found.append(f"{canary} in {name}")
    return found


def test_no_planted_secret_leaks_anywhere(
    db_client, leak_app, session_factory, audit_file, reports_dir, caplog
):
    caplog.set_level(logging.DEBUG)

    api = run_the_flow(db_client, leak_app)

    places = {
        "the database": database_text(session_factory),
        "the logs": caplog.text,
        "the audit log": audit_file.read_text(),
        "the requests to the AI": repr(leak_app.state.parts["agent"].requests),
        "the API answers": "\n".join(api.answers),
        "the report files": report_text(reports_dir),
    }
    assert leaks(places) == []


def test_sign_in_tokens_and_codes_stay_out_of_storage_and_logs(
    db_client, leak_app, session_factory, audit_file, caplog
):
    caplog.set_level(logging.DEBUG)

    api = run_the_flow(db_client, leak_app)

    places = {
        "the database": database_text(session_factory),
        "the logs": caplog.text,
        "the audit log": audit_file.read_text(),
    }
    assert leaks(places, api.sign_in_secrets) == []


def test_the_ai_requests_and_audit_log_were_searched(db_client, leak_app, audit_file):
    """Guards the leak test itself: an empty place would pass for the wrong reason."""
    run_the_flow(db_client, leak_app)

    requests = repr(leak_app.state.parts["agent"].requests)
    assert "ANALYZE" in requests
    assert "[MASKED:" in requests  # the masked findings reached the agent
    audit_log = audit_file.read_text()
    for event in ["MESSAGE_ADDED", "ACTION_BLOCKED", "TOOL_RUN_FINISHED", "SESSION_OPENED"]:
        assert event in audit_log


def test_the_masking_really_ran(db_client, leak_app, session_factory):
    run_the_flow(db_client, leak_app)

    with session_factory() as db:
        [run] = db.scalars(select(ToolRun)).all()
    assert run.masked_count >= 2
    assert "[MASKED:" in (run.output_masked or "")


def test_the_report_files_were_searched(db_client, leak_app, reports_dir):
    """Guards the leak test itself: an empty search would pass for the wrong reason."""
    run_the_flow(db_client, leak_app)

    assert sorted(path.suffix for path in reports_dir.rglob("report.*")) == [
        ".docx",
        ".json",
        ".pdf",
    ]
    assert "RCX-001" in report_text(reports_dir)


def test_the_provider_key_shows_only_its_last_4(db_client, leak_app):
    api = run_the_flow(db_client, leak_app)

    providers = api.call("GET", "/llm-providers").json()
    [added] = [p for p in providers if p["display_name"] == "Leak test"]
    assert PROVIDER_KEY[-4:] in str(added)
    assert PROVIDER_KEY not in str(added)
