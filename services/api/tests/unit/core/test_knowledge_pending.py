"""The store of knowledge add-ons waiting to be ingested: encrypted, private, never the file."""

import os
import stat

from cryptography.fernet import Fernet

from reconix_api.core import knowledge_pending
from reconix_api.core.config import Settings
from reconix_api.core.knowledge_add_ons import AddOn

ADD_ON = AddOn(
    knowledge_add_on_id="7d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    name="notes.md",
    kind="MD",
    size_bytes=20,
    chunk_count=1,
    interface="web",
    created_at="2026-11-05T10:00:00+00:00",
)


def settings_in(tmp_path, key: str | None = None) -> Settings:
    return Settings(
        provider_encryption_key=key or Fernet.generate_key().decode(),
        knowledge_pending_dir=str(tmp_path / "pending"),
    )


def test_it_keeps_the_passages_encrypted_in_a_private_folder(tmp_path):
    settings = settings_in(tmp_path)
    knowledge_pending.save(settings, ADD_ON, ["Rotate the vault keys on Friday."])

    [path] = list((tmp_path / "pending").iterdir())
    assert b"vault keys" not in path.read_bytes()
    assert stat.S_IMODE(os.stat(tmp_path / "pending").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert knowledge_pending.load(settings, ADD_ON.knowledge_add_on_id) == (
        ADD_ON,
        ["Rotate the vault keys on Friday."],
    )
    assert knowledge_pending.list_all(settings) == [ADD_ON]


def test_another_key_reads_nothing_and_remove_forgets(tmp_path):
    settings = settings_in(tmp_path)
    knowledge_pending.save(settings, ADD_ON, ["text"])
    other = settings_in(tmp_path)  # same folder, another key
    assert knowledge_pending.list_all(other) == []
    assert knowledge_pending.load(other, ADD_ON.knowledge_add_on_id) is None

    assert knowledge_pending.remove(settings, ADD_ON.knowledge_add_on_id) is True
    assert knowledge_pending.remove(settings, ADD_ON.knowledge_add_on_id) is False
    assert knowledge_pending.list_all(settings) == []


def test_nothing_is_made_until_something_waits(tmp_path):
    settings = settings_in(tmp_path)
    assert knowledge_pending.list_all(settings) == []
    assert not (tmp_path / "pending").exists()
