"""GET /knowledge/search, against Qdrant in this process and a fake embedder."""

from reconix_ai.knowledge import store
from reconix_api.core.knowledge_add_ons import KnowledgeStore
from tests.unit.api.test_knowledge_add_ons import fake_embed, make_client, upload


def test_knowledge_search_finds_an_upload(client, operator_headers):
    upload(client, operator_headers)

    hits = client.get(
        "/knowledge/search",
        params={"q": "payments service port", "source": "USER_DOC"},
        headers=operator_headers,
    )

    assert hits.status_code == 200, hits.json()
    assert hits.json()[0]["source"] == "USER_DOC"
    assert "8443" in hits.json()[0]["text"]


def test_knowledge_search_needs_a_query_and_known_sources(client, operator_headers):
    assert client.get("/knowledge/search", headers=operator_headers).status_code == 422
    bad = client.get(
        "/knowledge/search", params={"q": "x", "source": "NEWS"}, headers=operator_headers
    )
    assert bad.status_code == 422
    blank = client.get("/knowledge/search", params={"q": "   "}, headers=operator_headers)
    assert blank.status_code == 422
    assert blank.json()["code"] == "VALIDATION_ERROR"


def test_knowledge_search_with_qdrant_down_is_503(audit_events, operator_headers, settings):
    down = KnowledgeStore(client=store.connect("http://127.0.0.1:1"), embed=fake_embed)
    response = make_client(audit_events, down, settings).get(
        "/knowledge/search", params={"q": "sql injection"}, headers=operator_headers
    )
    assert response.status_code == 503
