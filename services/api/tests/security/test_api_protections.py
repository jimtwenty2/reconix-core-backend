"""Protections every endpoint gets: Host check, CORS, error shape, the session token.

There are no roles: a valid session token may do everything, so the token is the check.
"""

import re

import pytest

from reconix_api.main import API_PREFIX, create_app
from tests.fakes import build_fake_interfaces

WEB_ORIGIN = "http://127.0.0.1:3000"
ANY_ID = "00000000-0000-0000-0000-000000000001"
# The only endpoints that answer without a session token. POST /sessions gives one out.
OPEN = {("GET", "/health"), ("POST", "/sessions")}


def every_endpoint() -> list[tuple[str, str]]:
    """Every route, read from the app's own OpenAPI, so a new route is checked at once."""
    paths = create_app(build_fake_interfaces()[0]).openapi()["paths"]
    endpoints = []
    for path, operations in paths.items():
        local = re.sub(r"\{[^}]+\}", ANY_ID, path.removeprefix(API_PREFIX))
        endpoints += [(method.upper(), local) for method in operations]
    return sorted(endpoint for endpoint in endpoints if endpoint not in OPEN)


ENDPOINTS = every_endpoint()


def test_health_works_from_this_computer(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "OK"}


@pytest.mark.parametrize("host", ["evil.example", "192.168.1.10:8000", "127.0.0.1.evil.example"])
def test_wrong_host_header_is_rejected(client, host):
    response = client.get("/health", headers={"Host": host})
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_HOST"


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "localhost"])
def test_local_host_headers_are_accepted(client, host):
    assert client.get("/health", headers={"Host": host}).status_code == 200


def test_cors_allows_the_local_web(client):
    response = client.options(
        "/operator", headers={"Origin": WEB_ORIGIN, "Access-Control-Request-Method": "GET"}
    )
    assert response.headers.get("access-control-allow-origin") == WEB_ORIGIN


def test_cors_refuses_other_websites(client):
    response = client.options(
        "/operator",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in response.headers


def test_errors_use_the_one_shape(client):
    body = client.get("/does-not-exist").json()
    assert set(body) == {"code", "message", "details"}
    assert body["code"] == "NOT_FOUND"


def test_me_needs_a_token(client):
    response = client.get("/operator")
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_me_refuses_a_wrong_token(client):
    response = client.get("/operator", headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401


def test_me_returns_the_operator(client, operator_headers):
    me = client.get("/operator", headers=operator_headers).json()
    assert set(me) == {"session_id", "actor"}  # no role
    assert me["actor"] == "operator"


def test_the_list_holds_every_endpoint():
    assert len(ENDPOINTS) >= 40
    assert ("POST", f"/approvals/{ANY_ID}/approve") in ENDPOINTS
    assert ("GET", f"/reports/{ANY_ID}/download") in ENDPOINTS


@pytest.mark.parametrize(("method", "path"), ENDPOINTS)
def test_no_token_gets_401(client, method, path):
    response = client.request(method, path, json={})
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


@pytest.mark.parametrize(("method", "path"), ENDPOINTS)
def test_a_wrong_token_gets_401(client, method, path):
    headers = {"Authorization": "Bearer wrong"}
    assert client.request(method, path, headers=headers, json={}).status_code == 401
