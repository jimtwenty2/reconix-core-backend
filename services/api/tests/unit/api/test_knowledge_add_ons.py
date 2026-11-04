"""The /knowledge-add-ons routes, against Qdrant in this process and a fake embedder."""

import asyncio
import math
import zlib

import pytest
from fastapi.testclient import TestClient

from reconix_ai.knowledge import AddOn, KnowledgeFilters, Source, search_knowledge, store
from reconix_ai.knowledge.add_ons import add_on_chunk
from reconix_ai.providers import EMBEDDING_SIZE, ProviderError
from reconix_api.api.knowledge_add_ons import MAX_UPLOAD_BYTES
from reconix_api.core.knowledge_add_ons import KnowledgeStore
from reconix_api.core.knowledge_files import MAX_FILE_BYTES
from reconix_api.main import create_app
from reconix_api.services import knowledge_add_ons
from tests.fakes import build_fake_interfaces, fake_mask_secrets

RUNBOOK = b"# Runbook\n\nThe payments service listens on port 8443 behind the gateway.\n"


async def fake_embed(texts: list[str]) -> list[list[float]]:
    """Hashed word counts: similar words give similar vectors."""
    vectors = []
    for text in texts:
        values = [0.0] * EMBEDDING_SIZE
        for word in text.lower().split():
            values[zlib.crc32(word.encode()) % EMBEDDING_SIZE] += 1.0
        norm = math.sqrt(sum(v * v for v in values)) or 1.0
        vectors.append([v / norm for v in values])
    return vectors


async def model_down(texts: list[str]) -> list[list[float]]:
    raise ProviderError("MODEL_UNAVAILABLE", "The embedding model is not running.")


@pytest.fixture
def qdrant():
    return store.connect(":memory:")


@pytest.fixture
def audit_events():
    return []


def make_client(audit_events, store: KnowledgeStore) -> TestClient:
    interfaces, parts = build_fake_interfaces()
    parts["audit"].events = audit_events
    app = create_app(interfaces, mask_secrets=fake_mask_secrets, knowledge_store=store)
    return TestClient(app, base_url="http://127.0.0.1/api/v1")


@pytest.fixture
def client(qdrant, audit_events):
    return make_client(audit_events, KnowledgeStore(client=qdrant, embed=fake_embed))


def upload(client, headers, file_name="runbook.md", data=RUNBOOK, interface="cli", **form):
    files = {"file": (file_name, data, "application/octet-stream")}
    form = {"interface": interface, **form}
    return client.post("/knowledge-add-ons", headers=headers, files=files, data=form)


def test_an_upload_is_saved_listed_and_audited(client, operator_headers, audit_events):
    response = upload(client, operator_headers)

    assert response.status_code == 201
    added = response.json()
    assert added["name"] == "runbook.md"
    assert added["kind"] == "MD"
    assert added["size_bytes"] == len(RUNBOOK)
    assert added["chunk_count"] == 1
    assert added["interface"] == "cli"
    assert added["cut"] is None
    listed = client.get("/knowledge-add-ons", headers=operator_headers).json()
    assert [item["knowledge_add_on_id"] for item in listed] == [added["knowledge_add_on_id"]]
    [event] = audit_events
    assert event.event_type == "KNOWLEDGE_ADD_ON_ADDED"
    assert event.details["knowledge_add_on_id"] == added["knowledge_add_on_id"]


def test_the_agent_search_finds_an_upload(client, operator_headers, qdrant):
    upload(client, operator_headers)

    filters = KnowledgeFilters(sources=[Source.USER_DOC])
    hits = asyncio.run(
        search_knowledge("payments service port", filters, client=qdrant, embed=fake_embed)
    )

    assert "8443" in hits[0].text
    assert hits[0].title == "runbook.md"


def test_secrets_in_the_text_and_the_name_are_masked(client, operator_headers, qdrant):
    data = b"The deploy uses password=hunter2-very-secret on the jump host."

    response = upload(client, operator_headers, file_name="token=abc123secret.txt", data=data)

    assert "abc123secret" not in response.json()["name"]
    records, _ = asyncio.run(qdrant.scroll(store.COLLECTION, with_payload=True))
    assert "hunter2-very-secret" not in str(records)
    assert "abc123secret" not in str(records)


def test_the_name_field_is_shown_and_picks_the_type(client, operator_headers):
    without = upload(client, operator_headers, file_name="upload.bin", data=b'{"a": 1}')
    assert without.json()["code"] == "UNSUPPORTED_FILE_TYPE"

    named = upload(
        client, operator_headers, file_name="upload.bin", data=b'{"a": 1}', name="api.json"
    )
    assert named.status_code == 201
    assert named.json()["name"] == "api.json"
    assert named.json()["kind"] == "JSON"


def test_a_web_upload_says_so(client, operator_headers):
    assert upload(client, operator_headers, interface="web").json()["interface"] == "web"


@pytest.mark.parametrize("interface", ["WEB", "TERMINAL", ""])
def test_an_unknown_interface_is_refused(client, operator_headers, interface):
    response = upload(client, operator_headers, interface=interface)
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert response.json()["details"]["fields"][0]["field"] == "body.interface"


def test_an_upload_without_a_file_is_refused(client, operator_headers):
    response = client.post(
        "/knowledge-add-ons", headers=operator_headers, data={"interface": "cli"}
    )
    assert response.status_code == 422
    assert response.json()["details"]["fields"][0]["field"] == "body.file"


def test_a_body_over_the_limit_is_refused_unread(client, operator_headers):
    data = b"x" * (MAX_UPLOAD_BYTES + 1)
    response = upload(client, operator_headers, file_name="big.txt", data=data)
    assert response.status_code == 413
    assert response.json()["code"] == "FILE_TOO_LARGE"


def test_a_body_without_a_length_is_refused(client, operator_headers):
    headers = operator_headers | {"Content-Type": "multipart/form-data; boundary=x"}
    response = client.post("/knowledge-add-ons", headers=headers, content=iter([b"--x--"]))
    assert response.status_code == 411
    assert response.json()["code"] == "LENGTH_REQUIRED"


def test_an_unsupported_file_is_refused(client, operator_headers):
    response = upload(client, operator_headers, file_name="tool.exe")
    assert response.status_code == 422
    assert response.json()["code"] == "UNSUPPORTED_FILE_TYPE"


def test_a_file_over_10_mb_is_refused(client, operator_headers):
    response = upload(
        client, operator_headers, file_name="big.txt", data=b"x" * (MAX_FILE_BYTES + 1)
    )
    assert response.status_code == 413
    assert response.json()["code"] == "FILE_TOO_LARGE"


def test_a_file_without_text_is_refused(client, operator_headers):
    response = upload(client, operator_headers, file_name="empty.md", data=b"  \n\n ")
    assert response.status_code == 422
    assert response.json()["code"] == "FILE_HAS_NO_TEXT"


def test_the_add_on_limit_is_kept(client, operator_headers, monkeypatch):
    monkeypatch.setattr(knowledge_add_ons, "MAX_ADD_ONS", 1)
    upload(client, operator_headers)

    response = upload(client, operator_headers)

    assert response.status_code == 409
    assert response.json()["code"] == "KNOWLEDGE_ADD_ON_LIMIT"


def test_text_past_the_passage_limit_says_it_was_cut(client, operator_headers, monkeypatch):
    monkeypatch.setattr("reconix_ai.knowledge.add_ons.MAX_PASSAGES", 2)
    data = "\n\n".join("word " * 200 for _ in range(5)).encode()

    response = upload(client, operator_headers, file_name="long.txt", data=data)

    assert response.json()["chunk_count"] == 2
    assert response.json()["cut"] == "PASSAGE_LIMIT"


def test_remove_one(client, operator_headers, audit_events):
    keep = upload(client, operator_headers).json()["knowledge_add_on_id"]
    drop = upload(client, operator_headers).json()["knowledge_add_on_id"]

    response = client.delete(f"/knowledge-add-ons/{drop}", headers=operator_headers)

    assert response.status_code == 204
    listed = client.get("/knowledge-add-ons", headers=operator_headers).json()
    assert [item["knowledge_add_on_id"] for item in listed] == [keep]
    assert audit_events[-1].event_type == "KNOWLEDGE_ADD_ON_REMOVED"
    again = client.delete(f"/knowledge-add-ons/{drop}", headers=operator_headers)
    assert again.status_code == 404
    assert again.json()["code"] == "KNOWLEDGE_ADD_ON_NOT_FOUND"


def test_remove_clears_pieces_a_failed_save_left_behind(client, operator_headers, qdrant):
    orphan_id = "c0000000-0000-4000-8000-000000000003"
    orphan = AddOn(orphan_id, "half.md", "MD", 10, 1, "cli", "2026-10-30T09:00:00+00:00")
    piece = add_on_chunk(orphan, "half saved text", 0)
    asyncio.run(store.ensure_collection(qdrant))
    asyncio.run(store.save_chunks(qdrant, [piece], asyncio.run(fake_embed([piece.text]))))

    response = client.delete(f"/knowledge-add-ons/{orphan_id}", headers=operator_headers)

    assert response.status_code == 404
    records, _ = asyncio.run(qdrant.scroll(store.COLLECTION))
    assert records == []


def test_removing_an_unknown_add_on_is_audited(client, operator_headers, audit_events):
    unknown = "c0000000-0000-4000-8000-000000000004"

    response = client.delete(f"/knowledge-add-ons/{unknown}", headers=operator_headers)

    assert response.status_code == 404
    assert audit_events[-1].event_type == "KNOWLEDGE_ADD_ON_NOT_FOUND"
    assert audit_events[-1].details["knowledge_add_on_id"] == unknown


def test_secrets_in_json_are_masked_by_key_name(client, operator_headers, qdrant):
    data = b'{"Authorization": "ZXhhbXBsZTpzZWNyZXQ=", "db": {"password": "Pa\\"ss-Tail-1234"}}'

    assert upload(client, operator_headers, file_name="postman.json", data=data).status_code == 201

    records, _ = asyncio.run(qdrant.scroll(store.COLLECTION, with_payload=True))
    assert "ZXhhbXBsZTpzZWNyZXQ" not in str(records)
    assert "Tail-1234" not in str(records)


def test_remove_all(client, operator_headers, audit_events):
    upload(client, operator_headers)
    upload(client, operator_headers)

    response = client.delete("/knowledge-add-ons", headers=operator_headers)

    assert response.json() == {"removed_count": 2}
    assert client.get("/knowledge-add-ons", headers=operator_headers).json() == []
    assert audit_events[-1].event_type == "KNOWLEDGE_ADD_ONS_CLEARED"


def test_the_list_is_empty_before_any_upload(client, operator_headers):
    assert client.get("/knowledge-add-ons", headers=operator_headers).json() == []


def test_qdrant_down_answers_503(audit_events, operator_headers):
    down = KnowledgeStore(client=store.connect("http://127.0.0.1:1"), embed=fake_embed)
    client = make_client(audit_events, down)

    response = client.get("/knowledge-add-ons", headers=operator_headers)

    assert response.status_code == 503
    assert response.json()["code"] == "KNOWLEDGE_UNAVAILABLE"
    assert upload(client, operator_headers).status_code == 503
    assert audit_events == []


def test_the_embedding_model_down_answers_503_and_saves_nothing(
    qdrant, audit_events, operator_headers
):
    client = make_client(audit_events, KnowledgeStore(client=qdrant, embed=model_down))

    response = upload(client, operator_headers)

    assert response.status_code == 503
    assert response.json()["code"] == "MODEL_UNAVAILABLE"
    assert client.get("/knowledge-add-ons", headers=operator_headers).json() == []
    assert audit_events == []
