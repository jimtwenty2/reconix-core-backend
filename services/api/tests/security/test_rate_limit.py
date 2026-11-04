"""Too many requests: 429 with Retry-After, per session token, and a smaller sign-in limit."""

from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from reconix_api.core.config import Settings
from reconix_api.core.db import get_db
from reconix_api.core.errors import ApiError
from reconix_api.core.rate_limit import RateLimitMiddleware
from reconix_api.main import create_app
from tests.fakes import OPERATOR_TOKEN, build_fake_interfaces, fake_mask_secrets

HEADERS = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}


def limited_client(per_minute: int = 3, sign_in_per_minute: int = 2) -> TestClient:
    settings = Settings(
        rate_limit_per_minute=per_minute, sign_in_limit_per_minute=sign_in_per_minute
    )
    app = create_app(build_fake_interfaces()[0], settings=settings, mask_secrets=fake_mask_secrets)
    app.dependency_overrides[get_db] = no_database  # never the real one on this computer
    return TestClient(app, base_url="http://127.0.0.1/api/v1")


def no_database():
    raise ApiError(503, "NO_DATABASE_IN_THIS_TEST", "These tests use no database.")


def test_over_the_limit_is_429_with_retry_after():
    client = limited_client()
    answers = [client.get("/operator", headers=HEADERS) for _ in range(4)]
    assert [answer.status_code for answer in answers] == [200, 200, 200, 429]
    refused = answers[-1]
    assert refused.json()["code"] == "TOO_MANY_REQUESTS"
    assert 1 <= int(refused.headers["Retry-After"]) <= 60
    assert refused.json()["details"]["retry_after_seconds"] == int(refused.headers["Retry-After"])


def test_each_session_token_has_its_own_limit():
    client = limited_client(per_minute=1)
    assert client.get("/operator", headers=HEADERS).status_code == 200
    assert client.get("/operator", headers=HEADERS).status_code == 429
    other = {"Authorization": "Bearer another-fake-token"}
    assert client.get("/operator", headers=other).status_code == 401  # its own count


def test_signing_in_has_a_smaller_limit():
    client = limited_client(per_minute=100, sign_in_per_minute=2)
    answers = [client.post("/sessions", json={"interface": "cli"}) for _ in range(3)]
    assert [answer.status_code for answer in answers][-1] == 429
    guesses = client.post("/sessions/web-sign-in", json={"code": "fake-code"})
    assert guesses.status_code == 429  # the same sign-in limit covers both open routes


def test_the_limit_starts_again_each_minute():
    now = [0.0]
    app = Starlette(routes=[Route("/", lambda request: PlainTextResponse("ok"))])
    app.add_middleware(
        RateLimitMiddleware,
        per_minute=1,
        sign_in_per_minute=1,
        web_origins=[],
        clock=lambda: now[0],
    )
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.get("/").status_code == 429
    now[0] = 61.0
    assert client.get("/").status_code == 200


WEB = "http://127.0.0.1:3000"


def test_preflights_and_health_are_not_counted():
    client = limited_client(per_minute=1)
    preflight = {"Origin": WEB, "Access-Control-Request-Method": "GET"}
    for _ in range(3):
        assert client.options("/operator", headers=preflight).status_code == 200
        assert client.get("/health").status_code == 200
    assert client.get("/operator", headers=HEADERS).status_code == 200


def test_another_web_page_cannot_use_up_signing_in():
    """A page open in the browser can send requests to 127.0.0.1; they get their own bucket."""
    client = limited_client(per_minute=100, sign_in_per_minute=2)
    attacker = {"Origin": "http://attacker.example"}
    for _ in range(5):
        client.post("/sessions", json={"interface": "cli"}, headers=attacker)
    signed_in = client.post("/sessions", json={"interface": "cli"})
    assert signed_in.status_code != 429  # the real caller is not locked out


def test_the_local_web_can_read_a_429():
    client = limited_client(per_minute=1)
    headers = {**HEADERS, "Origin": WEB}
    client.get("/operator", headers=headers)
    refused = client.get("/operator", headers=headers)
    assert refused.status_code == 429
    assert refused.headers["access-control-allow-origin"] == WEB
    assert "retry-after" in refused.headers["access-control-expose-headers"].lower()
