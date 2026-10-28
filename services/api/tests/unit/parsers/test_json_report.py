import pytest

from reconix_api.parsers.json_report import JsonParseError, get, parse, pick


def test_document_that_is_a_list():
    assert parse('[{"a": 1}, {"a": 2}, "not an object"]') == [{"a": 1}, {"a": 2}]


def test_results_under_a_key():
    assert parse('{"results": [{"a": 1}]}', items="results[]") == [{"a": 1}]


def test_nested_lists():
    doc = {"Results": [{"Vulns": [{"id": 1}, {"id": 2}]}, {"Target": "no vulns"}]}
    assert pick(doc, "Results[].Vulns[]") == [{"id": 1}, {"id": 2}]


def test_json_lines():
    assert parse('{"a": 1}\n\n{"a": 2}\n', lines=True) == [{"a": 1}, {"a": 2}]


def test_cut_off_last_line_is_dropped():
    assert parse('{"a": 1}\n{"a": 2}\n{"a": ', lines=True) == [{"a": 1}, {"a": 2}]


def test_broken_line_in_the_middle_fails_cleanly():
    with pytest.raises(JsonParseError, match="line 2"):
        parse('{"a": 1}\nnot json\n{"a": 3}', lines=True)


@pytest.mark.parametrize("raw", ["", "   ", "not json", '{"results": ['])
def test_empty_or_broken_output_fails_cleanly(raw):
    with pytest.raises(JsonParseError):
        parse(raw, items="results[]")


def test_get_by_dotted_path():
    item = {"info": {"severity": "high"}, "matched-at": "http://x/"}
    assert get(item, "info.severity") == "high"
    assert get(item, "matched-at") == "http://x/"
    assert get(item, "info.missing.deeper") is None
