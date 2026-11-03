"""QA-011, QA-012, QA-014: what a typed line can do to the app.

A bracketed URL must be refused like any other bad target (it crashed the app), a credential
in the line must be masked wherever the line is recorded, and pasted control bytes or escape
sequences must never be drawn or stored.
"""

import pytest

from reconix import store
from reconix.screens import StartScreen
from reconix.store.parser import parse_request
from reconix.store.targets import check_target, validate_target

from .support import SIZE, settle, type_request

BRACKETED = [
    "http://x]x[",
    "scan http://a]b[ for issues",
    "http://[x/",
    "scan ports on http://x]y[",
]


# --- QA-011: a bracketed URL ----------------------------------------------------------------
@pytest.mark.parametrize("text", BRACKETED)
def test_a_bracketed_url_is_refused_not_raised(text):
    with pytest.raises(store.StoreValidationError, match="isn't a valid URL"):
        parse_request(text)


@pytest.mark.parametrize("template_id", ["network", "web_url", "api"])
def test_a_bracketed_url_is_refused_for_every_template(template_id):
    with pytest.raises(store.StoreValidationError):
        check_target(template_id, "http://x]x[")


def test_the_start_prompt_check_reads_a_bracketed_url_as_invalid():
    check = validate_target("http://x]x[")
    assert not check.valid and "isn't a valid URL" in check.error


def test_an_ipv6_literal_still_starts_a_run():
    parsed = parse_request("https://[::1]/")
    assert parsed is not None and parsed.target_url == "https://[::1]"


def test_a_provider_base_url_with_a_stray_bracket_is_refused():
    from reconix.store.providers import _require_http

    with pytest.raises(store.StoreValidationError, match="isn't a valid URL"):
        _require_http("http://x]x[/v1")


async def test_the_app_keeps_running_after_a_bracketed_url(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_request(pilot, "scan http://a]b[ for issues")
        await settle(pilot)
        assert app.is_running and isinstance(app.screen, StartScreen)
        assert not store.get_run().started
        await type_request(pilot, "https://[::1]/")  # a good line still works
        await settle(pilot)
        assert store.get_run().started


# --- QA-012: a credential in the typed line --------------------------------------------------
SECRET_LINE = "scan https://admin:S3cr3t-Pass@shop.example.com/login?token=abc123def"


def _recorded_texts():
    assessment = store.get_assessment()
    return (
        [entry.text for entry in assessment.chat]
        + [request.text for request in assessment.requests]
        + [event.detail for event in store.list_events()]
        + store.list_history()
    )


def test_a_credential_in_the_request_is_masked_everywhere_it_is_recorded():
    store.submit_prompt(SECRET_LINE)
    store.add_history(SECRET_LINE)
    recorded = "\n".join(_recorded_texts())
    assert "S3cr3t-Pass" not in recorded and "abc123def" not in recorded
    assert "https://••••@shop.example.com" in recorded
    # The target was still read from the line as typed, without the credential
    assert store.get_assessment().target_url == "https://shop.example.com"


def test_a_credential_in_a_line_without_a_target_is_masked():
    store.submit_prompt("my password=hunter22 is that ok")
    assert "hunter22" not in "\n".join(_recorded_texts())


def test_a_credential_in_a_chat_line_during_the_run_is_masked():
    store.start_run(store.DEMO_REQUEST)
    answer = store.say_operator_line("the token=abc123def works")
    assert "abc123def" not in answer  # what a model would be sent
    assert "abc123def" not in "\n".join(_recorded_texts())


# --- QA-014: control bytes and escape sequences ----------------------------------------------
PASTED = "scan https://shop.example.com\x07 \x1b[31mnow\x1b[0m\x00 \x1b]0;title\x07done"


def test_control_bytes_and_escape_sequences_never_reach_the_records():
    store.submit_prompt(PASTED)
    store.add_history(PASTED)
    for text in _recorded_texts():
        assert not any(ord(ch) < 32 for ch in text), repr(text)
        assert "[31m" not in text and "]0;" not in text, repr(text)
    assert store.list_requests()[0].text == "scan https://shop.example.com now done"


def test_a_line_of_only_control_bytes_is_empty():
    with pytest.raises(store.StoreValidationError, match="Type a request first"):
        store.submit_prompt("\x07\x1b[2J\x00")
