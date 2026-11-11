"""Core API mode: chat, the scope and the plan draft go through the local Core API.

A fake API stands in for the network (it answers like services/api does); the model is
never called directly in this mode.
"""

import json
from typing import Any, List, Optional, Tuple

import pytest

from reconix import core_api, store
from reconix.core_api import client, connect, scope_map
from reconix.llm import client as llm_client
from reconix.models import ScopeManifest

from .support import run_to
from .support import DEMO_REQUEST

URL = "http://127.0.0.1:8000"
TOKEN = "fake-session-token-0001"  # noqa: S105 - a fake


class FakeApi:
    """Answers the calls the app makes, and records them (method, path, body, auth)."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, str, Any, str]] = []
        self.providers: List[dict] = []
        self.reply = "The API's answer."
        self.fail: Optional[Tuple[int, str, str]] = None  # status, code, message
        self.down = False
        self.pending_activation = False  # activate answers 409 APPROVAL_PENDING
        self.plan_steps = [
            {
                "order": 1,
                "title": "Find the shop's pages",
                "phase": "discovery",
                "reason": "Start with what is there.",
                "action": {"tool": "ZAP", "target": "https://x/", "arguments": []},
            },
            {
                "order": 2,
                "title": "Check for known issues",
                "phase": "scan",
                "reason": "Then look for weaknesses.",
                "action": {"tool": "NUCLEI", "target": "https://x/", "arguments": []},
            },
        ]

    def paths(self) -> List[str]:
        return [f"{method} {path}" for method, path, _, _ in self.calls]

    def bodies(self, method: str, start: str) -> List[Any]:
        return [body for m, path, body, _ in self.calls if m == method and path.startswith(start)]

    def send(self, request, timeout=None) -> Any:
        if self.down:
            raise client.CoreApiError(
                "UNREACHABLE", "the Core API is not running (start it with reconix-api)"
            )
        path = request.full_url.split("/api/v1", 1)[1]
        body = json.loads(request.data) if request.data else None
        auth = request.headers.get("Authorization", "")
        self.calls.append((request.get_method(), path, body, auth))
        if self.fail and not path.startswith("/sessions") or (self.fail and path.endswith("/chat")):
            status, code, message = self.fail
            raise client.CoreApiError(code, message, status)
        return self.answer(request.get_method(), path, body)

    def answer(self, method: str, path: str, body: Any) -> Any:
        if path == "/sessions":
            return {"token": TOKEN, "session_id": "s-1"}
        if path == "/llm-providers" and method == "GET":
            return self.providers
        if path == "/llm-providers":
            row = {
                **body,
                "llm_provider_id": f"p-{len(self.providers)}",
                "is_active": False,
                "is_local": (body.get("base_url") or "").startswith("http://127.0.0.1"),
                "api_key_last4": (body.get("api_key") or "")[-4:] or None,
            }
            row.pop("api_key", None)
            self.providers.append(row)
            return row
        if path.endswith("/test") and path.startswith("/llm-providers/"):
            row = next(r for r in self.providers if path.split("/")[2] == r["llm_provider_id"])
            return {"ok": True, "model_name": row["model_name"], "latency_ms": 5}
        if path.endswith("/activate"):
            row = next(r for r in self.providers if path.split("/")[2] == r["llm_provider_id"])
            if row["is_local"]:
                row["is_active"] = True
                return {"llm_provider": row, "approval": None}
            if self.pending_activation:
                raise client.CoreApiError(
                    "APPROVAL_PENDING", "waits", 409, {"approval_id": "a-old"}
                )
            return {"llm_provider": row, "approval": {"approval_id": "a-cfg"}}
        if path.startswith("/approvals/"):
            return {}
        if path.endswith("/scope-manifests"):
            return {"manifest_id": "m-1"}
        if path.startswith("/scope-manifests/") and method == "PATCH":
            return {"manifest_id": "m-1"}
        if path.endswith("/submit"):
            return {"approval_id": "a-scope", "assessment": {"assessment_id": "as-1"}}
        if path.endswith("/chat"):
            return {"reply": {"content_masked": self.reply}}
        if path.endswith("/messages"):
            return {"message_id": "msg-1"}
        if "/plan" in path:
            return {"draft": True, "agent_run": {"agent_run_id": "r-1"}, "plan": self.plan_steps}
        if path.endswith("/discard"):
            return None
        raise AssertionError(f"unexpected call {method} {path}")


@pytest.fixture
def api(monkeypatch) -> FakeApi:
    fake = FakeApi()
    monkeypatch.setenv(client.ENV_URL, URL)
    monkeypatch.setattr(client, "_send", fake.send)
    connect.reset()
    yield fake
    connect.reset()


@pytest.fixture
def approved(api, model_active):
    """You said yes in /provider: the API may use the (remote) active model."""
    store.core_api_approve()


@pytest.fixture
def no_direct_model(monkeypatch):
    """In Core API mode the app never calls the model itself."""

    def refuse(*_args, **_kwargs):
        raise AssertionError("the model was called directly")

    monkeypatch.setattr(llm_client, "complete", refuse)
    monkeypatch.setattr(llm_client, "stream", refuse, raising=False)


def last_reply() -> str:
    return store.get_assessment().chat[-1].text


def test_on_by_default_at_this_computers_api(monkeypatch):
    monkeypatch.delenv(client.ENV_URL, raising=False)
    assert core_api.enabled()
    assert client.base_url() == client.DEFAULT_URL == "http://127.0.0.1:8000"


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5:8000",
        "https://api.example.com",
        "http://127.0.0.1:8000/x",
        "ftp://127.0.0.1",
    ],
)
def test_only_this_computer_is_allowed(monkeypatch, url):
    monkeypatch.setenv(client.ENV_URL, url)
    with pytest.raises(client.CoreApiError) as exc:
        client.base_url()
    assert exc.value.code == "NOT_LOCAL"


def test_a_question_is_answered_by_the_api(api, approved, no_direct_model):
    store.llm_answer("What does nmap -sV do?")

    assert last_reply() == "The API's answer."
    [body] = api.bodies("POST", "/sessions/s-1/chat")
    question, step = body["content"].split("\n")
    assert question == "What does nmap -sV do?"
    # The API's model doesn't see the app's steps: one line says where the flow is.
    assert step.startswith("(Reconix app: step ") and "the app's menu" in step
    chat_call = next(c for c in api.calls if c[1].endswith("/chat"))
    assert chat_call[3] == f"Bearer {TOKEN}"


def test_the_token_and_key_never_show(api, approved):
    store.llm_answer("hello")

    shown = " ".join(e.text for e in store.get_assessment().chat)
    shown += " ".join(a.message for a in store.list_activity())
    assert TOKEN not in shown and "sk-1234" not in shown


def test_an_api_that_is_down_is_said_plainly(api, approved, no_direct_model):
    api.down = True

    store.llm_answer("hello")

    texts = [e.text for e in store.get_assessment().chat]
    assert "thinking…" not in texts  # the placeholder is taken back out
    assert texts[-1].startswith("The AI couldn't answer: the Core API is not running")


def test_an_api_error_is_shown_as_the_api_said_it(api, approved, no_direct_model):
    api.fail = (503, "MODEL_UNAVAILABLE", "The model could not answer. Is it running?")

    store.llm_answer("hello")

    assert last_reply().startswith("The AI couldn't answer: The model could not answer.")


def test_a_plan_the_api_cant_draft_is_said_plainly(api, approved, no_direct_model):
    run_to("scope")
    store.approve_scope()
    request = store.plan_draft_request()
    api.down = True

    with pytest.raises(client.CoreApiError) as exc:
        store.fetch_plan_draft(request)
    store.plan_draft_failed(request, str(exc.value))

    assert not store.plan_drafting()
    assert any("couldn't draft the plan" in a.message for a in store.list_activity())


def test_the_scope_goes_to_the_api_and_follows_your_edits(api, approved, no_direct_model):
    run_to("scope")
    store.llm_answer("Is /admin in scope?")

    [draft] = api.bodies("POST", "/sessions/s-1/scope-manifests")
    assert draft["allowed_tools"] == [
        "WHATWEB",
        "KATANA",
        "NUCLEI",
        "TESTSSL",
        "FFUF",
        "NIKTO",
        "DALFOX",
    ]
    assert draft["targets"][0]["type"] == "url"
    assert {
        "type": "url",
        "value": draft["targets"][0]["value"] + "admin",
        "excluded": True,
    } in draft["targets"]

    # the assessment type first, so the API's AI plans the web techniques
    assert api.bodies("POST", "/sessions/s-1/messages") == [
        {"content": f"Assessment type: Web URL\n{DEMO_REQUEST}"}
    ]

    store.edit_scope(tools=["Nuclei"])
    store.llm_answer("And now?")

    [patched] = api.bodies("PATCH", "/scope-manifests/m-1")
    assert patched["allowed_tools"] == ["NUCLEI"]


def test_an_approved_scope_is_approved_on_the_api_and_the_plan_drafted(
    api, approved, no_direct_model
):
    run_to("scope")
    store.approve_scope()
    request = store.plan_draft_request()

    raw = store.fetch_plan_draft(request)
    assert store.apply_plan_draft(request, raw)

    paths = api.paths()
    assert "POST /scope-manifests/m-1/submit" in paths
    assert "POST /approvals/a-scope/approve" in paths
    assert "POST /assessments/as-1/plan?draft=true" in paths
    assert not any(p.endswith("/send") for p in paths)  # kept as a draft until Run plan
    tasks = {task.key: task for task in store.plan_tasks()}
    assert tasks["discovery"].label == "Find the shop's pages"
    assert tasks["discovery"].tools == ()  # ZAP is no longer in the web scope
    assert tasks["scanning"].tools == ("Nuclei",)


def test_a_new_assessment_gets_a_new_api_session(api, approved, no_direct_model):
    run_to("scope")
    store.llm_answer("first")
    store.new_assessment()
    run_to("scope")

    store.llm_answer("second")

    assert api.paths().count("POST /sessions") == 2


def network_scope(**values) -> ScopeManifest:
    base = dict(
        kind="network",
        target_url="10.0.0.0/24",
        assessment_type="Network",
        allowed_actions=["Host discovery", "port scan"],
        allowed_methods=["TCP connect"],
        excluded_paths=["10.0.0.9:22", "not a host!"],
        time_limit_minutes=30,
        tools=["nmap", "testssl.sh"],
        allowed_ports=[443, 22, 22],
    )
    return ScopeManifest(**{**base, **values})


def test_a_network_scope_in_the_apis_shape():
    draft = scope_map.scope_draft(network_scope())

    assert draft["allowed_tools"] == ["NMAP", "TESTSSL"]  # Kali catalog names
    assert draft["allowed_ports"] == [22, 443]
    assert draft["allowed_actions"] == ["discovery", "scan"]
    assert draft["allowed_methods"] == []
    assert draft["targets"] == [
        {"type": "cidr", "value": "10.0.0.0/24"},
        {"type": "ip", "value": "10.0.0.9", "excluded": True},
    ]


@pytest.mark.parametrize(
    ("values", "code"),
    [
        ({"kind": "source"}, "SCOPE_NOT_SUPPORTED"),
        ({"tools": []}, "NO_API_TOOLS"),
    ],
)
def test_a_scope_the_api_cant_take_is_refused(values, code):
    with pytest.raises(client.CoreApiError) as exc:
        scope_map.scope_draft(network_scope(**values))
    assert exc.value.code == code


def api_manifest(**values) -> ScopeManifest:
    base = dict(
        kind="api",
        target_url="http://api.example/",
        assessment_type="API",
        allowed_actions=["discovery", "scan"],
        allowed_methods=["GET"],
        excluded_paths=[],
        time_limit_minutes=30,
        tools=["schemathesis"],
    )
    return ScopeManifest(**{**base, **values})


def test_the_openapi_doc_url_is_sent_as_its_own_target():
    # So the API's schemathesis fuzzes /v3/api-docs, not a guessed <base>/openapi.json.
    draft = scope_map.scope_draft(api_manifest(), api_doc_url="http://api.example/v3/api-docs")

    assert draft["targets"][0] == {"type": "url", "value": "http://api.example/"}
    assert {"type": "url", "value": "http://api.example/v3/api-docs"} in draft["targets"]


def test_a_doc_url_equal_to_the_base_is_not_duplicated():
    draft = scope_map.scope_draft(api_manifest(), api_doc_url="http://api.example/")

    assert draft["targets"] == [{"type": "url", "value": "http://api.example/"}]


def test_the_spec_doc_url_comes_from_an_attached_spec():
    from reconix.core_api import sync
    from reconix.models import ApiSpec

    class _Holder:
        api_spec = None

    assert sync._spec_doc_url(_Holder()) is None
    holder = _Holder()
    holder.api_spec = ApiSpec(
        title="x",
        version="1",
        spec_version="3.0.3",
        file_name="api.example/v3/api-docs",
        source_url="http://api.example/v3/api-docs",
    )
    assert sync._spec_doc_url(holder) == "http://api.example/v3/api-docs"


async def test_choosing_a_remote_model_asks_for_the_core_apis_ok(api, app, reachable):
    from reconix.screens import ChoiceScreen

    from .support import SIZE, settle, screen_text

    store.set_provider("openai", api_key="sk-1234", models=["gpt-4o-mini"])
    store.test_provider("openai")
    async with app.run_test(size=SIZE) as pilot:
        app.activate_model("openai/gpt-4o-mini")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        shown = screen_text(app.screen)
        assert "Core API will send your scope" in shown and "sk-1234" not in shown
        assert "…1234" in shown  # only the key's last 4
        await pilot.press("enter")  # Approve (recommended, the default)
        await app.workers.wait_for_complete()
        await settle(pilot)
    assert "POST /approvals/a-cfg/approve" in api.paths()


async def test_not_now_approves_nothing(api, app, reachable):
    from .support import SIZE, settle

    store.set_provider("openai", api_key="sk-1234", models=["gpt-4o-mini"])
    store.test_provider("openai")
    async with app.run_test(size=SIZE) as pilot:
        app.activate_model("openai/gpt-4o-mini")
        await settle(pilot)
        await pilot.press("down", "enter")  # Not now
        await settle(pilot)
    assert not any("/approve" in p for p in api.paths())  # nothing approved
    assert store.core_api_needs_ok()  # the model stays pending
