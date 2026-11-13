"""The leak test for knowledge add-ons: plant fake secrets in uploads, look for them everywhere.

Fake secrets (canaries) go in through a file's text, a JSON key that names a secret, a
YAML block value, a Word table and the file name. Not one may show up in Qdrant (any
payload field), in what is sent to the embedding model, in the API's answers or in the
audit log. The masking is the real one; Qdrant runs in this process and the embedder is
a fake that keeps what it was sent.
"""

import asyncio
import io
import json

import pytest
from cryptography.fernet import Fernet
from docx import Document
from fastapi.testclient import TestClient

from reconix_ai.knowledge import store
from reconix_api.core.config import Settings, get_settings
from reconix_api.core.knowledge_add_ons import KnowledgeStore
from reconix_api.core.wiring import build_mask_secrets
from reconix_api.main import create_app
from tests.fakes import OPERATOR_TOKEN, build_fake_interfaces
from tests.unit.api.test_knowledge_add_ons import fake_embed

# Obvious fakes, each long and unusual, so a hit can only be a leak.
TEXT_PASSWORD = "LeakCanary-AddOn-Text-Passw0rd-5521"  # noqa: S105
HEADER_TOKEN = "LeakCanaryAddOnHeaderToken000000000077"  # noqa: S105
YAML_SECRET = "LeakCanary-AddOn-Yaml-Block-Secret-6630"  # noqa: S105
WORD_TOKEN = "ghp_LEAKCANARYADDONWORD00000000000000"  # noqa: S105
NAME_PASSWORD = "LeakCanary-AddOn-Name-Passw0rd-8814"  # noqa: S105
CANARIES = [TEXT_PASSWORD, HEADER_TOKEN, YAML_SECRET, WORD_TOKEN, NAME_PASSWORD]


def word_file() -> bytes:
    document = Document()
    document.add_paragraph("Service accounts for the staging cluster.")
    table = document.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "deploy bot"
    table.rows[0].cells[1].text = f"token {WORD_TOKEN}"
    out = io.BytesIO()
    document.save(out)
    return out.getvalue()


UPLOADS = [
    ("runbook.md", f"# Runbook\n\nLog in with password={TEXT_PASSWORD} on the jump host.\n"),
    (
        "postman.json",
        json.dumps({"request": {"headers": {"Authorization": f"Bearer {HEADER_TOKEN}"}}}),
    ),
    ("compose.yaml", f"services:\n  db:\n    secret: |\n      {YAML_SECRET}\n      second-line\n"),
    ("accounts.docx", word_file()),
    (f"password={NAME_PASSWORD}.txt", "A note whose file name holds a secret."),
]


@pytest.fixture
def leak_run(tmp_path):
    """Upload every file with the real masking; keep what each place saw."""
    qdrant = store.connect(":memory:")
    sent_to_model: list[str] = []

    async def keep_and_embed(texts: list[str]) -> list[list[float]]:
        sent_to_model.extend(texts)
        return await fake_embed(texts)

    interfaces, parts = build_fake_interfaces()
    app = create_app(
        interfaces,
        mask_secrets=build_mask_secrets(),
        knowledge_store=KnowledgeStore(client=qdrant, embed=keep_and_embed),
    )
    # a private folder for waiting add-ons, never the real one
    settings = Settings(
        provider_encryption_key=Fernet.generate_key().decode(),
        knowledge_pending_dir=str(tmp_path / "pending"),
    )
    app.dependency_overrides[get_settings] = lambda: settings
    client = TestClient(app, base_url="http://127.0.0.1/api/v1")
    headers = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}
    answers = []
    for file_name, content in UPLOADS:
        files = {"file": (file_name, content, "application/octet-stream")}
        response = client.post(
            "/knowledge-add-ons", headers=headers, files=files, data={"interface": "cli"}
        )
        assert response.status_code == 201, response.json()
        answers.append(response.text)
    answers.append(client.get("/knowledge-add-ons", headers=headers).text)
    records, _ = asyncio.run(qdrant.scroll(store.COLLECTION, limit=1000, with_payload=True))
    return {
        "qdrant": json.dumps([record.payload for record in records]),
        "embedding model": "\n".join(sent_to_model),
        "API answers": "\n".join(answers),
        "audit log": json.dumps([event.details for event in parts["audit"].events]),
        "point count": len(records),
    }


@pytest.mark.parametrize("place", ["qdrant", "embedding model", "API answers", "audit log"])
def test_no_planted_secret_leaks(leak_run, place):
    found = [canary for canary in CANARIES if canary in leak_run[place]]
    assert found == [], f"{place} holds {found}"


def test_every_upload_was_saved_and_searched(leak_run):
    """So the test above looked at real data, not an empty store."""
    assert leak_run["point count"] >= len(UPLOADS)
    assert "jump host" in leak_run["qdrant"]
    assert "deploy bot" in leak_run["qdrant"]
