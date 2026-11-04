from reconix_ai.agent.state import MAX_INPUT_CHARS, masked_texts


def test_a_secret_at_the_cut_is_masked_before_cutting() -> None:
    text = "a" * (MAX_INPUT_CHARS - 12) + " password=hunter2secret"

    [kept], count = masked_texts([text], keep=1)

    assert count == 1
    assert "hunter2" not in kept
    assert len(kept) <= MAX_INPUT_CHARS


def test_only_the_last_texts_are_kept() -> None:
    kept, _ = masked_texts(["one", "two", "three"], keep=2)

    assert kept == ["two", "three"]
