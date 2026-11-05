"""QA-005: a line that names a kind of test but no target gets Reconix's template hint at once;
a plain question goes to the Core API's AI (the app asks it in a worker)."""

from reconix import store
from reconix.store.run import submit_prompt
from reconix.store.targets import needs


def _last_reconix_line() -> str:
    return [c.text for c in store.get_assessment().chat if c.speaker == "reconix"][-1]


def test_a_keyword_line_gets_the_template_hint():
    assert submit_prompt("scan my network") == "answered"
    assert not store.get_run().started
    assert _last_reconix_line() == needs("network")
    assert "IPv4" in _last_reconix_line()


def test_a_plain_question_goes_to_the_core_apis_ai():
    assert submit_prompt("who are you?") == "ask"
    assert not store.get_run().started


def test_a_question_before_a_target_is_recorded_masked():
    assert submit_prompt("is password=hunter2 strong enough?") == "ask"
    line = store.get_assessment().chat[-1]
    assert line.speaker == "you" and "hunter2" not in line.text
