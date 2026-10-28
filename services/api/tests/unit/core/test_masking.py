import json

from reconix_ai.harness import mask_secrets
from reconix_api.core.masking import mask_json, mask_output

GENERIC = "tok9f8e7d6c5b4a39281706f5e4d3c2b1a0zz"  # no known shape: only its key name gives it away


def test_escaped_quotes_stay_valid_json_and_the_secret_goes():
    raw = json.dumps({"Line": 'client_secret: "9f8e7d6c5b4a39281706f5e4d3c2b1a0"'})
    masked, count = mask_output(mask_secrets, raw)
    assert json.loads(masked)["Line"] == 'client_secret: "[MASKED:api_key]"'
    assert "9f8e7d6c" not in masked
    assert count == 1


def test_value_under_a_secret_name_is_hidden_wherever_it_repeats():
    leak = {
        "RuleID": "generic-api-key",
        "Secret": GENERIC,
        "Match": f"service = {GENERIC}",
        "Line": f'service = "{GENERIC}"',
        "File": "config/settings.py",
    }
    masked, _ = mask_output(mask_secrets, json.dumps([leak]))
    assert GENERIC not in masked
    [item] = json.loads(masked)
    assert item["Secret"] == "[MASKED:token]"
    assert item["File"] == "config/settings.py"


def test_short_secret_values_are_not_replaced_everywhere():
    masked, _ = mask_output(mask_secrets, json.dumps({"token": "abc", "path": "/abc/file"}))
    assert json.loads(masked) == {"token": "[MASKED:token]", "path": "/abc/file"}


def test_json_lines_are_masked_line_by_line():
    raw = '{"a": "password=hunter2"}\n{"b": "fine"}\n{"c": "cut'
    masked, count = mask_output(mask_secrets, raw)
    first, second, last = masked.split("\n")
    assert json.loads(first) == {"a": "password=[MASKED:password]"}
    assert json.loads(second) == {"b": "fine"}
    assert last == '{"c": "cut'
    assert count == 1


def test_text_that_is_not_json_is_masked_as_text():
    assert mask_json(mask_secrets, "<nmaprun/>") is None
    assert mask_json(mask_secrets, "") is None
    assert mask_output(mask_secrets, "password=hunter2") == ("password=[MASKED:password]", 1)
