from reconix_ai.harness.masking import mask_secrets
from reconix_ai.harness.stream_masking import HOLD_BACK, StreamMasker

FILLER = "The scan found port 22 open on the host and nothing else of note today. " * 6


def stream(text: str, size: int) -> str:
    """Feed text in pieces of `size` characters; return everything released."""
    masker = StreamMasker()
    return "".join(masker.feed(text[i : i + size]) for i in range(0, len(text), size))


def test_short_text_is_held_back():
    assert StreamMasker().feed("hello there") == ""


def test_released_text_is_a_prefix_of_the_masked_whole():
    text = FILLER + "password=hunter2-not-real and more words follow here. " + FILLER
    for size in (1, 3, 7, 50):
        shown = stream(text, size)
        assert shown
        assert mask_secrets(text)[0].startswith(shown)


def test_a_secret_split_across_pieces_is_never_shown():
    secrets = [
        "password=hunter2-not-real",
        "api_key: sk-abcdefghijklmnopqrstuvwxyz123456",
        "Authorization: Bearer abcdefghijklmnop0123456789",
        "https://admin:s3cret-not-real@example.test/login",
        '"password": "two words-not-real"',
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    ]
    for secret in secrets:
        text = FILLER + secret + " " + FILLER
        for size in (1, 2, 5, 13):
            shown = stream(text, size)
            for part in ("hunter2", "abcdefghijklmnop", "s3cret", "two words", "ghp_abc"):
                assert part not in shown, (secret, size)


def test_a_change_to_shown_text_stops_the_release():
    masker = StreamMasker()
    masker._released = "something else"  # as if masking now reads differently
    assert masker.feed(FILLER + FILLER) == ""
    assert masker.feed(FILLER) == ""


def test_the_last_characters_stay_held_back():
    text = FILLER + FILLER
    shown = stream(text, 10)
    assert len(text) - len(shown) >= HOLD_BACK - 1


def test_a_long_quoted_secret_is_held_until_its_quote_closes():
    words = "long words of a passphrase " * 12  # far longer than HOLD_BACK
    text = FILLER + 'password: "' + words + '" ' + FILLER + FILLER
    for size in (3, 40):
        shown = stream(text, size)
        assert "passphrase" not in shown
        assert mask_secrets(text)[0].startswith(shown)


def test_a_long_secret_tag_is_held_until_it_closes():
    words = "long words of a passphrase " * 12
    text = FILLER + "<password>" + words + "</password> " + FILLER + FILLER
    for size in (3, 40):
        shown = stream(text, size)
        assert "passphrase" not in shown
        assert mask_secrets(text)[0].startswith(shown)


def test_an_unclosed_secret_holds_back_everything_after_it():
    text = FILLER + 'token = "never closed and goes on ' + FILLER + FILLER
    shown = stream(text, 10)
    assert "never closed" not in shown
    assert len(shown) <= len(FILLER)
