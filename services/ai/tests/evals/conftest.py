"""The live evals: the questions the knowledge search and the agent must keep answering.

They run against the live stack through its HTTP API, on the same paths the agent
uses (GET /knowledge/search wraps `search_knowledge`, POST /sessions/{id}/chat runs
the CHAT graph), so Qdrant and the embedding container never need publishing.
With no stack up everything skips clean.

    RECONIX_EVALS=1 pytest services/ai/tests/evals                        # no model calls
    RECONIX_EVALS=1 RECONIX_EVALS_MODEL=1 pytest services/ai/tests/evals  # chat questions too
"""

import os

import httpx
import pytest

API_URL = os.environ.get("RECONIX_API_URL", "http://127.0.0.1:8000")
V1 = API_URL + "/api/v1"
CHAT_TIMEOUT = 600.0  # a real model may take minutes for one answer


class Stack:
    """The live API with one open session; every call is made as that session."""

    def __init__(self, token: str, session_id: str) -> None:
        self.token = token
        self.session_id = session_id

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, path: str, **params) -> list[dict]:
        answer = httpx.get(f"{V1}{path}", headers=self.headers, params=params, timeout=60)
        answer.raise_for_status()
        return answer.json()

    def post(self, path: str, body: dict | None = None, timeout: float = 60.0) -> dict:
        answer = httpx.post(f"{V1}{path}", headers=self.headers, json=body, timeout=timeout)
        answer.raise_for_status()
        return answer.json()

    def ranks(self, query: str, limit: int = 3) -> list[str]:
        """The search's ref_ids, best first. Evals assert on these and never on score:
        a fused RRF score reaches 1.0 with no id in the query ("credential dumping"
        puts T1003 at 1.0), so a score proves nothing (T2 §1)."""
        return [hit["ref_id"] for hit in self.get("/knowledge/search", q=query, limit=limit)]

    def chat(self, content: str) -> str:
        """The agent's answer to a new message in this session."""
        return self.post(f"/sessions/{self.session_id}/chat", {"content": content}, CHAT_TIMEOUT)[
            "reply"
        ]["content_masked"]

    def close(self) -> None:
        httpx.post(f"{V1}/sessions/{self.session_id}/close", headers=self.headers, timeout=30)


def open_stack() -> Stack:
    """A new session on the live API, or a clean skip when the stack is not up."""
    if os.environ.get("RECONIX_EVALS") != "1":
        pytest.skip("live evals: run with RECONIX_EVALS=1 while the stack is up")
    try:
        opened = httpx.post(
            f"{V1}/sessions", json={"interface": "web", "operator": "evals"}, timeout=10
        )
        opened.raise_for_status()
    except httpx.HTTPError:
        pytest.skip(f"the live API at {API_URL} is not reachable")
    body = opened.json()
    return Stack(body["token"], body["session_id"])


@pytest.fixture(scope="module")
def stack() -> Stack:
    session = open_stack()
    yield session
    session.close()
