"""Shared fixtures: every test starts from fresh demo data, and the UI never waits."""

import sys
from pathlib import Path
from typing import List

import pytest

from reconix import browser, store, web_server
from reconix.app import ReconixApp
from reconix.flow import RunController
from reconix.llm import config as llm_config
from reconix.store import persist, report
from reconix.widgets import ChoiceMenu

# Test the harness that ships in this checkout (backend/), not any editable install elsewhere,
# so local backend/harness changes are exercised. Done at conftest import, before any test
# imports harness (reconix imports it lazily, so nothing above has pulled it in yet).
_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if _BACKEND.is_dir() and str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


@pytest.fixture(autouse=True)
def fake_api(monkeypatch):
    """Every call to the Core API lands on the fake API (tests/fakes/fake_api.py): the app's
    real client code runs, nothing reaches the network. Tests shape the run through it."""
    from reconix.core_api import client, connect

    from .fakes.fake_api import FakeApi

    fake = FakeApi()
    monkeypatch.setenv(client.ENV_URL, client.DEFAULT_URL)
    monkeypatch.setattr(client, "_send", fake.send)
    connect.reset()
    yield fake
    connect.reset()


@pytest.fixture(autouse=True)
def fresh_store():
    """The store lists are process-wide, so reset them around every test."""
    store.reset()
    yield
    store.reset()


@pytest.fixture(autouse=True)
def instant_ui(monkeypatch, tmp_path):
    """Steps play at once, menus take a pick at once (tests press keys on purpose); reports,
    saved assessments and the web link live in temp."""
    monkeypatch.setattr(RunController, "SPEED", 0)
    monkeypatch.setattr(ReconixApp, "ASK_PROVIDER_ON_START", False)  # tests opt in
    monkeypatch.setattr(ReconixApp, "SUGGEST_SCOPE_ON_REVIEW", False)  # tests opt in
    monkeypatch.setattr(ReconixApp, "CHECK_CORE_API_ON_START", False)  # tests opt in
    monkeypatch.setattr(ChoiceMenu, "ARM_DELAY", 0)
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(persist, "DATA_DIR", tmp_path / "assessments")
    monkeypatch.setattr(persist, "WEB_URL_FILE", tmp_path / "web.url")
    monkeypatch.setattr(persist, "ENABLED", True)  # tests save to the tmp dir above
    monkeypatch.setattr(persist, "_written", {})


@pytest.fixture(autouse=True)
def llm_paths(monkeypatch, tmp_path):
    """Keep the LLM database and key file in temp, never in ~/.reconix."""
    monkeypatch.setattr(llm_config, "DB_PATH", tmp_path / "llm.db")
    monkeypatch.setattr(llm_config, "KEY_FILE", tmp_path / "llm.key")


@pytest.fixture(autouse=True)
def knowledge_dir(monkeypatch, tmp_path):
    """Point the /add-on knowledge folder at temp, never ~/.reconix/knowledge."""
    from reconix.store.knowledge import paths

    monkeypatch.setattr(paths, "KNOWLEDGE_DIR", tmp_path / "knowledge")
    monkeypatch.setenv("RECONIX_KNOWLEDGE_KEY_FILE", str(tmp_path / "keys" / "knowledge.key"))


@pytest.fixture
def reports_dir(tmp_path):
    """Where instant_ui sends the reports this test writes."""
    return tmp_path / "reports"


@pytest.fixture
def reachable(monkeypatch):
    """Every provider reachability test passes without touching the network."""
    from reconix.llm import client

    monkeypatch.setattr(client, "ping", lambda pid, model, **kw: (True, "reachable"))


@pytest.fixture(autouse=True)
def stream_via_complete(monkeypatch):
    """The app streams model replies; tests fake `client.complete`, so a stream replays that
    reply as one chunk (and never reaches the network)."""
    from reconix.llm import client

    def stream(pid, model, messages, on_text, **kw):
        text = client.complete(pid, model, messages, **kw)
        on_text(text)
        return text

    monkeypatch.setattr(client, "stream", stream)


@pytest.fixture
def model_active(reachable):
    """A configured, tested and active model on the Core API."""
    store.set_provider("openai", api_key="sk-1234", models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    if store.core_api_needs_ok():  # a model off this computer: approve it
        store.core_api_approve()


@pytest.fixture(autouse=True)
def opened(monkeypatch) -> List[str]:
    """Nothing a test does may launch a real browser: record what would have opened."""
    calls: List[str] = []
    monkeypatch.setattr(browser, "open_url", lambda url: calls.append(url) or True)
    monkeypatch.setattr(browser, "open_path", lambda path: calls.append(path) or True)
    return calls


class FakeDashboard:
    """Stands in for the `npm run dev` process: running until stopped."""

    def __init__(self) -> None:
        self.stopped = False
        self.pid = -1

    def poll(self):
        return 0 if self.stopped else None


@pytest.fixture(autouse=True)
def web_launches(monkeypatch) -> List[object]:
    """Nothing a test does may start a real web dashboard: record what would have run.

    Each started FakeDashboard is appended; "install" marks an `npm install`. The real
    readiness check is kept (nothing listens, so it never looks ready unless a test says).
    """
    calls: List[object] = []

    def start(data_dir, url_file):
        calls.append(FakeDashboard())
        return calls[-1]

    monkeypatch.setattr(web_server, "install", lambda: calls.append("install") or True)
    monkeypatch.setattr(web_server, "start", start)
    monkeypatch.setattr(web_server, "stop", lambda process: setattr(process, "stopped", True))
    monkeypatch.setattr(web_server, "problem", lambda: "")
    monkeypatch.setattr(web_server, "needs_install", lambda: False)
    return calls


@pytest.fixture
def app() -> ReconixApp:
    return ReconixApp()
