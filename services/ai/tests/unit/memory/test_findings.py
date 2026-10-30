import pytest

from reconix_ai.knowledge import KnowledgeError, store
from reconix_ai.memory import AcceptedFinding, forget_finding, remember_finding, search_findings
from tests.unit.knowledge.fakes import FakeEmbedder

CLIENT_A = "11111111-1111-1111-1111-111111111111"
CLIENT_B = "22222222-2222-2222-2222-222222222222"


def accepted(finding_id: str, assessment_id: str = CLIENT_A, **values) -> AcceptedFinding:
    fields = {
        "code": "RCX-001",
        "title": "Anonymous FTP login",
        "target": "172.20.0.5",
        "description": "vsftpd allows anonymous login on port 21.",
        "severity_status": "MEDIUM",
        "finding_status": "OPEN",
        "cwe_ids": ["CWE-287"],
        **values,
    }
    return AcceptedFinding(finding_id=finding_id, assessment_id=assessment_id, **fields)


@pytest.fixture
def client():
    return store.connect(":memory:")


@pytest.fixture
def embedder() -> FakeEmbedder:
    return FakeEmbedder()


async def remember(client, embedder, finding: AcceptedFinding) -> int:
    return await remember_finding(finding, client=client, embed=embedder.embed)


async def search(client, embedder, query: str, assessment_id: str = CLIENT_A, limit: int = 5):
    return await search_findings(query, assessment_id, limit, client=client, embed=embedder.embed)


async def test_a_remembered_finding_is_found_by_meaning_and_words(client, embedder):
    await remember(client, embedder, accepted("f-1"))
    sqli = {"code": "RCX-002", "title": "SQL injection in login", "description": "The id is"}
    await remember(client, embedder, accepted("f-2", **sqli))

    hits = await search(client, embedder, "anonymous ftp")

    assert hits[0].code == "RCX-001"
    assert hits[0].finding_status == "OPEN"
    assert "Target: 172.20.0.5" in hits[0].text and "CWE-287" in hits[0].text


async def test_a_search_never_sees_another_assessment(client, embedder):
    await remember(client, embedder, accepted("f-1", assessment_id=CLIENT_B))

    assert await search(client, embedder, "anonymous ftp", assessment_id=CLIENT_A) == []
    assert len(await search(client, embedder, "anonymous ftp", assessment_id=CLIENT_B)) == 1


async def test_a_new_review_replaces_the_finding(client, embedder):
    await remember(client, embedder, accepted("f-1"))
    await remember(client, embedder, accepted("f-1", finding_status="FIXED"))

    hits = await search(client, embedder, "anonymous ftp")

    assert [hit.finding_status for hit in hits] == ["FIXED"]


async def test_a_forgotten_finding_is_gone(client, embedder):
    await remember(client, embedder, accepted("f-1"))

    await forget_finding("f-1", client=client)

    assert await search(client, embedder, "anonymous ftp") == []


async def test_forgetting_before_anything_was_remembered_is_fine(client):
    await forget_finding("f-1", client=client)


async def test_secrets_are_masked_before_embedding_and_saving(client, embedder):
    leaky = accepted("f-1", description="Banner shows password=hunter2secret on login.")

    hidden = await remember(client, embedder, leaky)

    assert hidden == 1
    assert not any("hunter2secret" in text for text in embedder.texts)
    records, _ = await client.scroll("findings", with_payload=True)
    assert "hunter2secret" not in repr(records)
    await search(client, embedder, "password=hunter2secret")
    assert not any("hunter2secret" in text for text in embedder.texts)


async def test_nothing_remembered_yet_finds_nothing(client, embedder):
    assert await search(client, embedder, "anything") == []
    assert await search(client, embedder, "   ") == []


async def test_reloading_the_knowledge_keeps_the_findings(client, embedder):
    await remember(client, embedder, accepted("f-1"))

    await store.create_collection(client)  # what every knowledge ingest does

    assert len(await search(client, embedder, "anonymous ftp")) == 1


async def test_qdrant_down_is_a_clear_error(embedder):
    down = store.connect("http://127.0.0.1:9")  # nothing listens on the discard port

    with pytest.raises(KnowledgeError) as error:
        await remember(down, embedder, accepted("f-1"))

    assert error.value.code == "KNOWLEDGE_UNAVAILABLE"
