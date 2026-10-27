"""Protections every endpoint gets: Host check, CORS, error shape, roles."""

import pytest
from fastapi import APIRouter

from reconix_api.core.security import RequireOperator

WEB_ORIGIN = "http://127.0.0.1:3000"


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
        "/me", headers={"Origin": WEB_ORIGIN, "Access-Control-Request-Method": "GET"}
    )
    assert response.headers.get("access-control-allow-origin") == WEB_ORIGIN


def test_cors_refuses_other_websites(client):
    response = client.options(
        "/me",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in response.headers


def test_errors_use_the_one_shape(client):
    body = client.get("/does-not-exist").json()
    assert set(body) == {"code", "message", "details"}
    assert body["code"] == "NOT_FOUND"


def test_me_needs_a_token(client):
    response = client.get("/me")
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_me_refuses_a_wrong_token(client):
    response = client.get("/me", headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401


def test_me_returns_the_operator(client, operator_headers, viewer_headers):
    assert client.get("/me", headers=operator_headers).json()["role"] == "OPERATOR"
    assert client.get("/me", headers=viewer_headers).json()["role"] == "VIEWER"


def test_viewer_cannot_change_data(app, client, operator_headers, viewer_headers):
    router = APIRouter()

    @router.post("/_test/change")
    def change(_: RequireOperator) -> dict:
        return {"changed": True}

    app.include_router(router)
    assert client.post("/_test/change", headers=operator_headers).status_code == 200
    response = client.post("/_test/change", headers=viewer_headers)
    assert response.status_code == 403
    assert response.json()["code"] == "VIEWER_READ_ONLY"
