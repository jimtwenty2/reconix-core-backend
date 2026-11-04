import json
import os
import stat
import uuid

import pytest
from cryptography.fernet import Fernet

from reconix_ai.harness.disclosure import DisclosureError, DisclosureVault, mask_and_keep
from reconix_ai.harness.masking import mask_secrets

# Fake secrets, built from parts so secret scanners do not flag this file.
GITHUB_TOKEN = "ghp_" + "a1B2" * 9
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
OPENAI_KEY = "sk-" + "proj" + "Q" * 24
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjMifQ" + ".c2lnbmF0dXJl"
PRIVATE_KEY = (
    "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA " + "PRIVATE KEY-----"
)

SAMPLES = [
    "nothing to hide here",
    "password=hunter22",
    '{"password": "hunter 22", "api_key": "' + OPENAI_KEY + '"}',
    "http://bob:hunter22@juice-shop.lab/ and Authorization: Bearer " + JWT,
    "token=" + GITHUB_TOKEN + " then " + AWS_KEY + " then " + GITHUB_TOKEN,
    "key:\n" + PRIVATE_KEY + "\nend",
    "Cookie: session=abc; " + PRIVATE_KEY.replace("\n", " "),
    "<password>s3cr3t</password><apiToken>tok-123456</apiToken>",
    "already [MASKED:password] and password=new-one",
    "fake [MASKED:token#00000000-0] label, password=x1",
    "PASSWORD: hunter22 next\nDB_PASSWORD='it''s' pwd=\"q w e\"",
]


@pytest.fixture
def vault(tmp_path):
    return DisclosureVault(tmp_path / "vault", Fernet(Fernet.generate_key()))


@pytest.mark.parametrize("text", SAMPLES)
def test_masked_text_and_count_match_mask_secrets(text: str) -> None:
    masked, count, _ = mask_and_keep(text)
    assert (masked, count) == mask_secrets(text)


def test_real_values_are_kept_in_the_order_they_appear() -> None:
    text = "token=" + GITHUB_TOKEN + " then " + AWS_KEY + " and password=hunter22"
    masked, count, hidden = mask_and_keep(text)
    assert count == 3
    assert [(item.index, item.kind, item.value) for item in hidden] == [
        (0, "token", GITHUB_TOKEN),
        (1, "api_key", AWS_KEY),
        (2, "password", "hunter22"),
    ]
    for item in hidden:
        assert masked[item.start :].startswith(f"[MASKED:{item.kind}]")


def test_labels_that_were_already_there_are_not_counted() -> None:
    masked, count, hidden = mask_and_keep("old [MASKED:token] new password=hunter22")
    assert count == 1
    assert [(item.index, item.value) for item in hidden] == [(0, "hunter22")]
    assert masked[hidden[0].start :].startswith("[MASKED:password]")


def test_a_secret_inside_another_secret_is_kept_whole() -> None:
    text = "Cookie: session=abc; " + PRIVATE_KEY.replace("\n", " ")
    masked, _, hidden = mask_and_keep(text)
    assert masked == "Cookie: [MASKED:token]"
    assert [(item.kind, item.value) for item in hidden] == [("token", text[len("Cookie: ") :])]


def test_a_fake_numbered_label_in_the_text_is_left_alone() -> None:
    text = "fake [MASKED:token#00000000-0] label, password=x1"
    masked, _, hidden = mask_and_keep(text)
    assert masked == "fake [MASKED:token#00000000-0] label, password=[MASKED:password]"
    assert [item.value for item in hidden] == ["x1"]


def test_nothing_hidden_gives_an_empty_list() -> None:
    assert mask_and_keep("just text") == ("just text", 0, [])


def test_keep_then_reveal_one_value(vault) -> None:
    evidence_id = uuid.uuid4()
    _, _, hidden = mask_and_keep("password=hunter22 token=" + GITHUB_TOKEN)
    vault.keep(evidence_id, hidden)
    assert [(item.index, item.kind) for item in vault.kinds(evidence_id)] == [
        (0, "password"),
        (1, "token"),
    ]
    assert vault.reveal(evidence_id, 1).value == GITHUB_TOKEN
    assert vault.reveal(str(evidence_id), 0).value == "hunter22"


def test_values_are_encrypted_on_disk(vault) -> None:
    evidence_id = uuid.uuid4()
    _, _, hidden = mask_and_keep("password=hunter22 token=" + GITHUB_TOKEN)
    vault.keep(evidence_id, hidden)
    data = vault.path(evidence_id).read_bytes()
    assert b"hunter22" not in data
    assert GITHUB_TOKEN.encode() not in data
    with pytest.raises(json.JSONDecodeError):
        json.loads(data)


def test_only_this_user_can_open_the_folder_and_files(vault) -> None:
    vault.folder.mkdir(mode=0o755)
    evidence_id = uuid.uuid4()
    vault.keep(evidence_id, mask_and_keep("password=hunter22")[2])
    assert stat.S_IMODE(os.stat(vault.folder).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(vault.path(evidence_id)).st_mode) == 0o600
    assert list(vault.folder.iterdir()) == [vault.path(evidence_id)]  # no temporary file left


def test_nothing_hidden_saves_nothing(vault) -> None:
    evidence_id = uuid.uuid4()
    vault.keep(evidence_id, [])
    assert not vault.folder.exists()
    assert vault.kinds(evidence_id) == []


def test_keep_again_replaces_the_values(vault) -> None:
    evidence_id = uuid.uuid4()
    vault.keep(evidence_id, mask_and_keep("password=first1")[2])
    vault.keep(evidence_id, mask_and_keep("password=second2")[2])
    assert vault.reveal(evidence_id, 0).value == "second2"


@pytest.mark.parametrize("index", [-1, 1, 99, True, "0", 0.0])
def test_a_wrong_index_is_refused(vault, index) -> None:
    evidence_id = uuid.uuid4()
    vault.keep(evidence_id, mask_and_keep("password=hunter22")[2])
    with pytest.raises(DisclosureError) as error:
        vault.reveal(evidence_id, index)
    assert error.value.code == "BAD_INDEX"


def test_unknown_evidence_is_not_found(vault) -> None:
    with pytest.raises(DisclosureError) as error:
        vault.reveal(uuid.uuid4(), 0)
    assert error.value.code == "NOT_FOUND"


@pytest.mark.parametrize("evidence_id", ["../../etc/passwd", "", "abc", "/etc/x"])
def test_an_id_that_is_not_a_uuid_is_refused(vault, evidence_id) -> None:
    for call in (
        lambda: vault.keep(evidence_id, mask_and_keep("password=hunter22")[2]),
        lambda: vault.reveal(evidence_id, 0),
        lambda: vault.kinds(evidence_id),
        lambda: vault.forget(evidence_id),
    ):
        with pytest.raises(DisclosureError) as error:
            call()
        assert error.value.code == "BAD_EVIDENCE_ID"


def test_a_wrong_key_cannot_read_the_values(vault) -> None:
    evidence_id = uuid.uuid4()
    vault.keep(evidence_id, mask_and_keep("password=hunter22")[2])
    other = DisclosureVault(vault.folder, Fernet(Fernet.generate_key()))
    with pytest.raises(DisclosureError) as error:
        other.reveal(evidence_id, 0)
    assert error.value.code == "UNREADABLE"


def test_a_symlink_in_place_of_the_file_is_not_read(vault, tmp_path) -> None:
    evidence_id = uuid.uuid4()
    vault.keep(uuid.uuid4(), mask_and_keep("password=hunter22")[2])  # makes the folder
    target = tmp_path / "elsewhere"
    target.write_bytes(b"x")
    vault.path(evidence_id).symlink_to(target)
    with pytest.raises(DisclosureError) as error:
        vault.reveal(evidence_id, 0)
    assert error.value.code == "UNREADABLE"


def test_a_symlink_in_place_of_the_folder_is_refused(tmp_path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "vault"
    link.symlink_to(real)
    vault = DisclosureVault(link, Fernet(Fernet.generate_key()))
    with pytest.raises(NotADirectoryError):
        vault.keep(uuid.uuid4(), mask_and_keep("password=hunter22")[2])


def test_forget_deletes_the_values(vault) -> None:
    evidence_id = uuid.uuid4()
    vault.keep(evidence_id, mask_and_keep("password=hunter22")[2])
    vault.forget(evidence_id)
    vault.forget(evidence_id)  # a second time is fine
    assert vault.kinds(evidence_id) == []
