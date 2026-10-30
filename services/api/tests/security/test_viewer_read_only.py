"""A viewer can only look: every endpoint that changes data answers 403."""

import pytest

ANY_ID = "00000000-0000-0000-0000-000000000001"

CHANGES = [
    ("POST", f"/sessions/{ANY_ID}/scope-manifests"),
    ("PATCH", f"/scope-manifests/{ANY_ID}"),
    ("POST", f"/scope-manifests/{ANY_ID}/submit"),
    ("POST", f"/sessions/{ANY_ID}/close"),
    ("PATCH", f"/assessments/{ANY_ID}"),
    ("DELETE", f"/assessments/{ANY_ID}"),
    ("PATCH", f"/findings/{ANY_ID}"),
    ("POST", f"/approvals/{ANY_ID}/approve"),
    ("POST", f"/approvals/{ANY_ID}/reject"),
    ("POST", f"/assessments/{ANY_ID}/actions"),
    ("POST", f"/assessments/{ANY_ID}/plan"),
    ("POST", f"/assessments/{ANY_ID}/analyze"),
    ("POST", f"/assessments/{ANY_ID}/reports"),
    ("POST", f"/reports/{ANY_ID}/review-requests"),
    ("POST", f"/sessions/{ANY_ID}/messages"),
    ("POST", "/llm-providers"),
    ("PATCH", f"/llm-providers/{ANY_ID}"),
    ("DELETE", f"/llm-providers/{ANY_ID}"),
    ("POST", f"/llm-providers/{ANY_ID}/activate"),
]


@pytest.mark.parametrize(("method", "path"), CHANGES)
def test_viewer_gets_403(client, viewer_headers, method, path):
    response = client.request(method, path, headers=viewer_headers, json={})
    assert response.status_code == 403
    assert response.json()["code"] == "VIEWER_READ_ONLY"


@pytest.mark.parametrize(("method", "path"), CHANGES)
def test_no_token_gets_401(client, method, path):
    assert client.request(method, path, json={}).status_code == 401
