"""A viewer can only look: every endpoint that changes data answers 403."""

import pytest

ANY_ID = "00000000-0000-0000-0000-000000000001"

CHANGES = [
    ("POST", "/scopes"),
    ("PUT", f"/scopes/{ANY_ID}"),
    ("POST", f"/scopes/{ANY_ID}/submit"),
    ("POST", f"/approvals/{ANY_ID}/approve"),
    ("POST", f"/approvals/{ANY_ID}/reject"),
    ("POST", f"/assessments/{ANY_ID}/actions"),
]


@pytest.mark.parametrize(("method", "path"), CHANGES)
def test_viewer_gets_403(client, viewer_headers, method, path):
    response = client.request(method, path, headers=viewer_headers, json={})
    assert response.status_code == 403
    assert response.json()["code"] == "VIEWER_READ_ONLY"


@pytest.mark.parametrize(("method", "path"), CHANGES)
def test_no_token_gets_401(client, method, path):
    assert client.request(method, path, json={}).status_code == 401
