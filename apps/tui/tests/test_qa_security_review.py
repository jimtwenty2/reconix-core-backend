"""Fixes from the security review of the QA pass.

A key never rides in a provider's base URL; an error message never shows a typed password;
invisible and 8-bit control characters never reach a record; the Core API's AI gets the
masked line.
"""

import pytest

from reconix import store
from reconix.store.redact import clean, redact
from reconix.store.targets import validate_target

from .support import run_to


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


# --- 6. the Core API's AI gets the masked line ------------------------------------------------
def test_the_core_api_chat_gets_the_masked_line(fake_api, reachable):
    store.set_provider("openai", api_key="sk-1234", models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    store.core_api_approve()  # your OK in /provider for the remote model
    run_to("scope")
    store.say_to_assistant("check https://admin:S3cr3tPw@app.example.com token=abc123def456")
    sent = [body["content"] for _, path, body, _ in fake_api.calls
            if path.endswith(("/chat", "/messages")) and body]
    assert sent
    assert all("S3cr3tPw" not in text and "abc123def456" not in text for text in sent)
