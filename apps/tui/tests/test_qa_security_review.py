"""Fixes from the security review of the QA pass.

A rejected validation leaves no record of having run; a key never rides in a provider's base
URL; an error message never shows a typed password; invisible and 8-bit control characters
never reach a record; the agent's model gets the masked line.
"""

import pytest

from reconix import store
from reconix.store.redact import clean, redact
from reconix.store.run import EVIDENCE_PENDING, EVIDENCE_REJECTED
from reconix.store.targets import validate_target

from .support import decide, play_until_gate, run_to


def _chat() -> str:
    return "\n".join(entry.text for entry in store.get_assessment().chat)


def _activity() -> str:
    return "\n".join(entry.message for entry in store.list_activity())


def _play(decisions):
    """Decide the two approvals as given ("approve" / "reject"), the rest as usual."""
    run_to("approval:approval-001")
    for gate, choice in zip(("approval:approval-001", "approval:approval-002"), decisions):
        assert store.waiting_gate() == gate
        if choice == "reject":
            store.reject(gate.split(":", 1)[1])
        else:
            decide(gate)
        play_until_gate()
    assert store.is_completed()


# --- 1. a rejected validation is never reported as run -------------------------------------
def test_the_candidate_has_no_evidence_until_its_validation_runs():
    run_to("approval:approval-001")
    finding = store.get_finding("001")
    assert finding.validation == "UNCONFIRMED"
    assert finding.evidence == [EVIDENCE_PENDING]
    assert finding.description.startswith("Suspected issue")


def test_a_rejected_high_validation_leaves_no_trace_of_running():
    _play(["approve", "reject"])
    finding = store.get_finding("001")
    assert finding.validation == "UNCONFIRMED"
    assert finding.evidence == [EVIDENCE_REJECTED]
    assert "order record owned by test account B" not in finding.description
    assert "Validation completed" not in _chat()
    assert "Evidence recorded" not in _activity()
    assert "Running limited validation" not in _activity()


def test_a_rejected_baseline_keeps_the_high_evidence_but_never_confirms():
    _play(["reject", "approve"])
    finding = store.get_finding("001")
    assert finding.validation == "UNCONFIRMED"
    assert finding.evidence and finding.evidence != [EVIDENCE_REJECTED]
    assert "part of its validation was rejected" in _activity()


def test_both_checks_approved_confirm_with_the_real_evidence():
    _play(["approve", "approve"])
    finding = store.get_finding("001")
    assert finding.validation == "CONFIRMED"
    assert EVIDENCE_PENDING not in finding.evidence


# --- 2. no key in a provider's base URL ------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "http://:sk-secretvalue@remote.example.com/v1",
        "http://user:pw@remote.example.com/v1",
        "https://user@remote.example.com/v1",
    ],
)
def test_a_base_url_with_credentials_is_refused(url):
    from reconix.store.providers import _require_http

    with pytest.raises(store.StoreValidationError, match="key field"):
        _require_http(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/v1",
        "http://[fd00:ec2::254]/v1",
        "http://metadata.google.internal/v1",
    ],
)
def test_a_cloud_metadata_address_is_refused(url):
    from reconix.store.providers import _require_http

    with pytest.raises(store.StoreValidationError, match="metadata"):
        _require_http(url)


def test_a_normal_base_url_is_kept():
    from reconix.store.providers import _require_http

    assert _require_http("http://127.0.0.1:11434/v1") == "http://127.0.0.1:11434/v1"


# --- 3. an error never shows a typed password ------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "https://admin:S3cr3tPw@app.example.com:99999/",
        "https://admin:S3cr3tPw@app.example.com]x[/",
    ],
)
def test_a_bad_target_error_masks_the_password(text):
    check = validate_target(text)
    assert not check.valid and "S3cr3tPw" not in check.error
    with pytest.raises(store.StoreValidationError) as raised:
        store.submit_prompt(f"scan {text}")
    assert "S3cr3tPw" not in str(raised.value)


# --- 4. 8-bit controls and invisible characters ------------------------------------------------
@pytest.mark.parametrize("text", ["scan \x9b31mred\x9b0m", "\x9d0;title\x9c", "a\x7fb", "x‮y"])
def test_8_bit_controls_and_bidi_overrides_are_dropped(text):
    cleaned = clean(text)
    assert not any(0x7F <= ord(ch) <= 0x9F or ch == "‮" for ch in cleaned)


@pytest.mark.parametrize("text", ["token​=abc123def456", "pass­word: hunter22"])
def test_an_invisible_character_cannot_hide_a_secret_from_the_mask(text):
    assert "abc123def456" not in redact(text) and "hunter22" not in redact(text)


# --- 6. agent mode sends the masked line ------------------------------------------------------
def test_the_agent_gets_the_masked_line(app, monkeypatch):
    sent = []
    monkeypatch.setattr(app, "_agent_worker", lambda text, gen: sent.append(text))
    monkeypatch.setattr(app, "run_worker", lambda fn, **kwargs: fn())
    monkeypatch.setattr(app, "refresh_view", lambda: None)
    monkeypatch.setattr(app, "notify", lambda *args, **kwargs: None)
    app._send_to_agent("check https://admin:S3cr3tPw@app.example.com token=abc123def456")
    assert sent and "S3cr3tPw" not in sent[0] and "abc123def456" not in sent[0]
