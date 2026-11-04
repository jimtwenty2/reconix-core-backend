"""QA-005: with the mock model set, a line that names a kind of test but no target gets
Reconix's template hint, not the mock's fallback."""

from reconix import store
from reconix.store.run import submit_prompt
from reconix.store.targets import needs


def _last_reconix_line() -> str:
    return [c.text for c in store.get_assessment().chat if c.speaker == "reconix"][-1]


def test_a_keyword_line_gets_the_template_hint_with_the_mock_active():
    store.use_mock()
    assert submit_prompt("scan my network") == "answered"
    assert not store.get_run().started
    assert _last_reconix_line() == needs("network")
    assert "IPv4" in _last_reconix_line()


def test_a_plain_question_still_goes_to_the_mock():
    store.use_mock()
    assert submit_prompt("who are you?") == "ask"
    assert not store.get_run().started


def test_without_a_model_the_keyword_line_gets_the_same_hint():
    assert submit_prompt("scan my network") == "answered"
    assert _last_reconix_line() == needs("network")
