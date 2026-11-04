"""The web dashboard masks pasted secrets with a port of `redact()`
(web/src/lib/assistant/redact.ts) and lists of strings with a port of `redact_lines()`
(web/src/lib/report/mask.ts); both test suites check the same cases
(web/tests/redact-vectors.json, web/tests/redact-list-vectors.json), so the two stay in step."""

import json
import re
from pathlib import Path

import pytest

from reconix.store.redact import (
    HIDDEN_LINE, clean, escaped_secret, redact, redact_all, strip_controls,
)

_DIR = Path(__file__).parents[2] / "web" / "tests"   # apps/web/tests
_REPEAT = re.compile(r"\{\{(.)\*(\d+)\}\}")


def _expand(text: str) -> str:
    """A long fake key is written "{{X*N}}" in the shared file (X repeated N times), so no file
    holds a key-shaped string a secret scanner would flag (web/tests/vectors.ts does the same)."""
    return _REPEAT.sub(lambda m: m.group(1) * int(m.group(2)), text)


VECTORS = [(_expand(text), _expand(masked)) for text, masked in
           json.loads((_DIR / "redact-vectors.json").read_text("utf-8"))]
LIST_VECTORS = json.loads((_DIR / "redact-list-vectors.json").read_text("utf-8"))


@pytest.mark.parametrize("text, masked", VECTORS)
def test_the_web_port_masks_the_same_way(text, masked):
    assert redact(text) == masked


@pytest.mark.parametrize("items, masked", LIST_VECTORS)
def test_a_list_of_strings_is_masked_as_one_text_like_the_web(items, masked):
    assert redact_all(items) == masked
    assert redact_all({"evidence": items}) == {"evidence": masked}


def test_a_private_key_stored_one_line_per_evidence_entry_is_masked_whole():
    body = ["MIIEowIBAAKCAQEAs3cr3tK3yB0dyL1ne0ne", "Zm9vYmFyYmF6cXV4c2VjcmV0bGluZXR3bw"]
    finding = {"evidence": ["GET /backup/key.pem → 200", "-----BEGIN PRIVATE KEY-----", *body,
                            "-----END PRIVATE KEY-----", "Content-Type: text/plain"]}
    masked = redact_all({"findings": [finding]})["findings"][0]["evidence"]
    assert not any(line in text for line in body for text in masked)
    assert masked == ["GET /backup/key.pem → 200", "•••• (private key)",
                      "Content-Type: text/plain"]


def test_a_list_of_other_values_is_masked_item_by_item():
    assert redact_all([1, "password=x", None]) == [1, "password=••••", None]
    assert redact_all([{"a": "token=abc"}, "Cookie: sid=1"]) == [{"a": "token=••••"},
                                                                  "Cookie: ••••"]


def test_clean_turns_escape_sequences_and_control_characters_into_spaces():
    # A whole sequence is one space (no "[31m" left, no two words glued); DEL and the C1
    # controls go too (U+009B / U+009D are 8-bit CSI / OSC)
    assert clean("a\x00b\x1b[31mc\x07\x0b\x0c\x7fd￾￿e") == "a b c    d  e"
    assert clean("tab\there\nline\r\nend") == "tab\there\nline\r\nend"
    assert clean("lone \ud800 surrogate") == "lone ? surrogate"
    assert clean("10.0.0.1\x1b(Bnext \x90q\x9cend \x1b]0;title\x07x") == "10.0.0.1 next  end  x"
    # A secret behind a control character: no reading is sure to mask it, the line is hidden
    assert redact_all(["x\x00\n\x00y", "\x1bpassword=hunter2"]) == ["x \n y", HIDDEN_LINE]


@pytest.mark.parametrize("text", [
    "10.0.0.1\x00token=SUPERSECRET1",          # glued, the masking misses it
    "pass\x00word=SUPERSECRET1",                # spaced, the masking misses it
    "\x1b[31token=SUPERSECRET1",                # the CSI's final byte eats the "t"
    "\x1bpassword=hunter2",                     # ESC p is a sequence of its own
])
def test_a_secret_behind_control_characters_is_found(text):
    assert escaped_secret(text)
    assert redact(text) == HIDDEN_LINE


def test_control_characters_without_a_secret_only_become_spaces():
    assert not escaped_secret("scan 10.0.0.1\x1b[31mred\x1b[0m\x00end")
    assert not escaped_secret("password=x")              # no control character: plain masking
    assert strip_controls("scan 10.0.0.1\x1b[31mred") == "scan 10.0.0.1 red"
    # only the lines that hide a secret go; the others are masked as usual
    assert redact("a\nb\x00token=x\nc password=y") == f"a\n{HIDDEN_LINE}\nc password=••••"
