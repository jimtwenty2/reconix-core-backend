"""QA-011, QA-012, QA-014: what a typed line can do to the app.

A bracketed URL must be refused like any other bad target (it crashed the app), a credential
in the line must be masked wherever the line is recorded, and pasted control bytes or escape
sequences must never be drawn or stored.
"""

import pytest

from reconix import store
from reconix.screens import StartScreen
from reconix.store.assessment import HIDDEN_LINE, fold_line
from reconix.store.parser import parse_request
from reconix.store.redact import MASK
from reconix.store.targets import check_target, validate_target

from .support import SIZE, run_to, run_ui_to, settle, toasts, type_request

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


# A pasted coloured line: the escape sequences go, the words around them stay apart, so the
# target is still read (it was "scan 10.0.0.1redend" and no run started).
COLOURED = "scan 10.0.0.1\x1b[31mred\x1b[0m\x00end"


def test_an_escape_sequence_never_glues_the_target_to_the_next_word():
    assert fold_line(COLOURED) == "scan 10.0.0.1 red end"
    assert store.submit_prompt(COLOURED) == "started"
    assert store.get_assessment().target == "10.0.0.1"
    assert store.list_requests()[0].text == "scan 10.0.0.1 red end"


@pytest.mark.parametrize(
    "text",
    [
        "scan 10.0.0.1\x9b31mred",  # 8-bit CSI (U+009B)
        "scan 10.0.0.1\x1b]0;title\x07red",  # OSC ended by BEL
        "scan 10.0.0.1\x9d0;title\x9cred",  # 8-bit OSC ended by 8-bit ST
    ],
)
def test_every_escape_shape_leaves_the_target_readable(text):
    assert fold_line(text) == "scan 10.0.0.1 red"
    assert check_target("network", text).target == "10.0.0.1"


# Colour codes next to a secret: neither the spaced form ("pass word=…") nor the glued one
# ("10.0.0.1token=…") can be masked reliably, so the typed line is refused and never kept.
# A key-shaped fake built at runtime, so no file holds a string the commit's secret scan flags
_AKIA = "AKIA" + "B" * 16
ESCAPED_SECRETS = [
    ("scan 10.0.0.1 pass\x1b[0mword=secret1", "secret1"),  # a split key name
    ("scan 10.0.0.1 to\x1b[31mken=secret2", "secret2"),
    ("scan 10.0.0.1 api\x1b]0;x\x07_key: secret3", "secret3"),
    ("scan 10.0.0.1 \x1b[33mpassword\x1b[0m=secret4", "secret4"),  # a coloured name
    # A decoy secret made the glued form win, which hid the second one (security review):
    ("password=a Bearer\x1b[0mabcdefghijklmnop", "abcdefghijklmnop"),
    ("password=a 10.0.0.1\x1b[31mtoken=SUPERSECRET1", "SUPERSECRET1"),
    ("token=x a\x1b[0mcookie=SID123", "SID123"),
    ("pwd=x id\x1b[0m" + _AKIA, _AKIA),
    ("scan 10.0.0.1\x1b[31mred password=abc", "abc"),  # a target next to a code and a secret
    ("pass\x1b[0mword=secret1", "secret1"),
    # Not only CSI/OSC: every control byte or invisible character glued a secret on (review 2)
    ("10.0.0.1\x00token=SUPERSECRET1", "SUPERSECRET1"),
    ("a\x1bMcookie=SID123", "SID123"),
    ("10.0.0.1\x1b(Btoken=SUPERSECRET1", "SUPERSECRET1"),
    ("10.0.0.1\x07token=SUPERSECRET1", "SUPERSECRET1"),
    ("10.0.0.1\x85token=SUPERSECRET1", "SUPERSECRET1"),
    ("10.0.0.1\u200btoken=SUPERSECRET1", "SUPERSECRET1"),
    ("10.0.0.1\x90q\x9ctoken=SUPERSECRET1", "SUPERSECRET1"),  # 8-bit DCS
    ("10.0.0.1\x9fabc\x9ctoken=SUPERSECRET1", "SUPERSECRET1"),  # 8-bit APC
    ("10.0.0.1 \x1b[31token=SUPERSECRET1", "SUPERSECRET1"),  # a partial CSI eats the "t"
    ("pass\x1b(Bword=SUPERSECRET1", "SUPERSECRET1"),
    ("Bearer\x00abcdefghijklmnop", "abcdefghijklmnop"),
    ("id\x00" + _AKIA, _AKIA),
]


@pytest.mark.parametrize("text, secret", ESCAPED_SECRETS)
def test_colour_codes_next_to_a_secret_are_refused(text, secret):
    with pytest.raises(store.StoreValidationError, match="Remove the colour or control codes"):
        store.recorded_line(text)
    with pytest.raises(store.StoreValidationError, match="Remove the colour or control codes"):
        store.submit_prompt(text)
    assert not store.get_run().started
    for recorded in _recorded_texts():
        assert secret not in recorded, repr(recorded)


@pytest.mark.parametrize("text, secret", ESCAPED_SECRETS)
def test_colour_codes_next_to_a_secret_never_reach_history_feedback_or_folding(text, secret):
    history, feedback = list(store.list_history()), store.list_feedback()
    with pytest.raises(store.StoreValidationError, match="Remove the colour or control codes"):
        store.add_history(text)
    with pytest.raises(store.StoreValidationError, match="Remove the colour or control codes"):
        store.add_feedback("scope", text)
    assert store.list_history() == history and store.list_feedback() == feedback
    assert fold_line(text) == HIDDEN_LINE  # callers that can't refuse keep nothing


@pytest.mark.parametrize("text, secret", ESCAPED_SECRETS)
def test_control_codes_next_to_a_secret_are_refused_in_the_chat(text, secret):
    run_to("scope")
    before = len(store.get_assessment().chat)
    with pytest.raises(store.StoreValidationError, match="Remove the colour or control codes"):
        store.say_operator_line(text)
    assert len(store.get_assessment().chat) == before
    for recorded in _recorded_texts():
        assert secret not in recorded, repr(recorded)


def test_esc_then_a_letter_next_to_a_secret_is_refused():
    with pytest.raises(store.StoreValidationError, match="Remove the colour or control codes"):
        store.recorded_line("10.0.0.1\x1btoken=SUPERSECRET1")


def test_a_coloured_line_without_a_secret_is_still_accepted():
    assert store.recorded_line("scan 10.0.0.1 \x1b[1mnow\x1b[0m") == "scan 10.0.0.1 now"
    assert store.recorded_line("scan 10.0.0.1 password=abc") == f"scan 10.0.0.1 password={MASK}"


async def test_the_start_prompt_refuses_colour_codes_next_to_a_secret(app):
    async with app.run_test(size=SIZE) as pilot:
        await type_request(pilot, "scan 10.0.0.1\x1b[31mred password=sk-1234")
        await settle(pilot)
        assert app.is_running and isinstance(app.screen, StartScreen)
        assert not store.get_run().started
        assert any("Remove the colour or control codes" in t for t in toasts(app))
        for recorded in _recorded_texts():
            assert "sk-1234" not in recorded, repr(recorded)
        await type_request(pilot, COLOURED)  # the same line without a secret still starts
        await settle(pilot)
        assert store.get_run().started and store.get_assessment().target == "10.0.0.1"


def test_a_line_of_only_control_bytes_is_empty():
    with pytest.raises(store.StoreValidationError, match="Type a request first"):
        store.submit_prompt("\x07\x1b[2J\x00")


# --- R3: "Type something." feedback is masked like a recorded line ---------------------------
def test_feedback_is_masked_in_the_list_and_the_audit_line():
    store.add_feedback("scope", "a token=SUPERSECRET1")
    assert store.list_feedback()[-1].text == f"a token={MASK}"
    details = [event.detail for event in store.list_events()]
    assert f"a token={MASK}" in details
    assert not any("SUPERSECRET1" in detail for detail in details)


# --- R4: the command bar at the target login --------------------------------------------------
@pytest.mark.parametrize("line", ["/S3cretPass", "/new something", "/plan", "/stop now"])
async def test_the_command_bar_at_the_target_login_runs_and_keeps_nothing(app, line):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "account")
        assessments, history = len(store.list_assessments()), store.list_history()
        screen = app.screen
        assert app.run_command_line(line) is False
        await settle(pilot)
        assert app.screen is screen and store.waiting_gate() == "account"
        assert len(store.list_assessments()) == assessments
        assert store.list_history() == history                     # nothing kept
        shown = toasts(app)
        assert any("target login" in t for t in shown)
        assert not any(line.split()[0][1:] in t for t in shown if "Unknown" in t)


async def test_stop_and_help_still_work_at_the_target_login(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "account")
        assert app.run_command_line("/help") is True
        await settle(pilot)
        assert store.waiting_gate() == "account"   # nothing decided


# --- R5: error messages repeat typed text masked ---------------------------------------------
def test_a_scope_error_repeats_the_typed_value_masked():
    run_to("scope")
    with pytest.raises(store.StoreValidationError) as raised:
        store.edit_scope(tools=["https://user:S3cr3t@x.example.com"])
    assert "S3cr3t" not in str(raised.value) and MASK in str(raised.value)


def test_an_unknown_command_repeats_the_name_masked():
    from reconix.commands import COMMANDS, check_command_line

    check = check_command_line(COMMANDS, "/token=SUPERSECRET1")
    assert not check.ok and "SUPERSECRET1" not in check.error and MASK in check.error
    check = check_command_line(COMMANDS, "/export password=hunter2", object())
    assert "hunter2" not in check.error
