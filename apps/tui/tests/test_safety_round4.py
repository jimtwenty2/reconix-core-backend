"""Safety round 4: env-style secret names, secrets Reconix holds masked by value, a tab inside
a secret's name, "my password is …" phrases, excluded source folders at any depth, and no
network call when LiteLLM is imported."""

import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from reconix import store
from reconix.store import known_secrets, persist
from reconix.store.policy import repo_path_reason
from reconix.store.redact import HIDDEN_LINE, MASK, escaped_secret, redact

from .support import TEST_PASSWORD, play_until_gate, run_to

SHORT_KEY = "sk-fake-0000-1234"  # a fake key too short for the sk- shape  # noqa: S105
PROVIDER = "openai"
FIRST_KEY, OTHER_KEY = "first-key-1111", "other-key-2222"


def _with_test_login() -> None:
    """A run to the end, with the test account (TEST_PASSWORD) kept in this assessment's
    vault, the way the target login stores it."""
    from reconix.models.vault import Secret, VaultEntry

    run_to(None)
    store.get_assessment().vault.append(
        VaultEntry("password", Secret(TEST_PASSWORD), identity="demo.tester"))


def _recorded_texts():
    assessment = store.get_assessment()
    return (
        [entry.text for entry in assessment.chat]
        + [request.text for request in assessment.requests]
        + [entry.message for entry in store.list_activity()]
        + [event.detail for event in store.list_events()]
        + [entry.text for entry in store.list_feedback()]
        + store.list_history()
    )


# --- S1: a keyword at the end of a longer name ---------------------------------------------------
@pytest.mark.parametrize(
    "text, masked",
    [
        ("DB_PASSWORD=hunter22", f"DB_PASSWORD={MASK}"),
        ("OPENAI_API_KEY=abcdef12", f"OPENAI_API_KEY={MASK}"),
        ("AWS_SECRET_ACCESS_KEY=wJalrXUtn", f"AWS_SECRET_ACCESS_KEY={MASK}"),
        ("MYSQL_ROOT_PASSWORD: rootpw1", f"MYSQL_ROOT_PASSWORD: {MASK}"),
        ("auth_token=abc123", f"auth_token={MASK}"),
        ("pass=letmein", f"pass={MASK}"),
        ("--password=hunter22", f"--password={MASK}"),
        ("private_key=MIIEabc", f"private_key={MASK}"),
        ("passport=X123 bypass=1 compass: north", "passport=X123 bypass=1 compass: north"),
    ],
)
def test_an_env_style_name_keeps_its_name_and_loses_its_value(text, masked):
    assert redact(text) == masked


# A rule that may start after every "_" or "-" of a long run and scan the rest of it from there
# is quadratic: these 1 MB runs would take hours; linear they take well under a second.
@pytest.mark.parametrize("unit", ["a_", "a-", "_pass", "pass ", "token is ", "x\t", "DB_PASSWORD"])
def test_the_keyword_rules_are_linear_on_long_runs(unit):
    text = unit * (1024 * 1024 // len(unit))
    started = time.perf_counter()
    redact(text)
    assert time.perf_counter() - started < 3.0


# --- S2: secrets Reconix holds, masked by their value -------------------------------------------
def test_the_target_login_password_is_masked_wherever_it_is_typed():
    _with_test_login()
    assert TEST_PASSWORD in known_secrets.values()
    line = f"does {TEST_PASSWORD} still work"
    sent = store.say_operator_line(line)  # what a model would be sent
    assert TEST_PASSWORD not in sent and MASK in sent
    store.add_history(line)
    store.add_feedback("account", line)
    assert not any(TEST_PASSWORD in text for text in _recorded_texts())
    store.autosave()
    for path in persist.DATA_DIR.glob("*.json"):
        assert TEST_PASSWORD not in path.read_text("utf-8")


def test_a_saved_model_key_is_masked_in_a_typed_line():
    assert redact(f"key {SHORT_KEY}") == f"key {SHORT_KEY}"  # no shape catches it
    store.set_provider(PROVIDER, api_key=SHORT_KEY, models=["gpt-4o-mini"])
    assert redact(f"key {SHORT_KEY}") == f"key {MASK}"
    store.submit_prompt(f"my key is {SHORT_KEY} ok?")
    store.add_history(f"use {SHORT_KEY}")
    assert not any(SHORT_KEY in text for text in _recorded_texts())


def test_a_changed_model_key_is_masked_and_the_old_one_no_longer_is():
    store.set_provider(PROVIDER, api_key=FIRST_KEY, models=["gpt-4o-mini"])
    assert redact("first-key-1111") == MASK
    store.set_provider(PROVIDER, api_key=OTHER_KEY, models=["gpt-4o-mini"])
    assert redact("other-key-2222 first-key-1111") == f"{MASK} first-key-1111"
    store.unset_provider(PROVIDER)
    assert redact("other-key-2222") == "other-key-2222"


def test_short_values_are_not_masked_and_longer_ones_go_first(monkeypatch):
    monkeypatch.setattr(known_secrets, "_provider_values", lambda: ("abcd", "abcd1234", "xyz"))
    assert known_secrets.values() == ["abcd1234", "abcd"]
    assert redact("abcd1234 abcd xyz") == f"{MASK} {MASK} xyz"


def test_reading_the_keys_creates_no_settings_or_key_file():
    from reconix.llm import config

    assert not config.DB_PATH.exists() and not config.KEY_FILE.exists()
    assert known_secrets.values() == []
    assert not config.DB_PATH.exists() and not config.KEY_FILE.exists()


def test_a_login_value_behind_a_control_character_hides_the_line():
    _with_test_login()
    half = len(TEST_PASSWORD) // 2
    hidden = TEST_PASSWORD[:half] + "\x00" + TEST_PASSWORD[half:]
    assert escaped_secret(hidden) and redact(f"x {hidden}") == HIDDEN_LINE


# --- S3: a tab inside a secret's name ------------------------------------------------------------
def test_a_tab_inside_a_secrets_name_is_refused_in_a_typed_line():
    with pytest.raises(store.StoreValidationError, match="control codes"):
        store.submit_prompt("pass\tword=SECRET1")
    assert redact("pass\tword=SECRET1") == HIDDEN_LINE
    assert not escaped_secret("name\tvalue")  # a tab alone is fine


# --- S4: "my password is …" ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "text, masked",
    [
        ("my password is hunter2", f"my password is {MASK}"),
        ("the passphrase is correct-horse", f"the passphrase is {MASK}"),
        ("the api key is sk-1234", f"the api key is {MASK}"),
        ("Token is: q1w2e3", f"Token is: {MASK}"),
        ("the token is invalid", "the token is invalid"),
        ("sk-1234 stays", "sk-1234 stays"),
    ],
)
def test_a_secret_named_in_a_sentence_is_masked(text, masked):
    assert redact(text) == masked


def test_a_phrase_in_a_typed_line_never_reaches_the_records():
    store.submit_prompt("scan app.example.com, my password is hunter22x")
    assert not any("hunter22x" in text for text in _recorded_texts())


# --- S5: excluded source folders at any depth, encoded traversal ----------------------------------
EXCLUDED = [".git", "node_modules", "secrets", "config/keys"]


@pytest.mark.parametrize(
    "target",
    [
        ".git/config",
        "app/.git/config",
        "secrets/key.pem",
        "app/secrets/prod.env",
        "a/b/node_modules/x.js",
        "x/config/keys/a",
        "config/keys",
        "APP/Secrets/x",
    ],
)
def test_an_excluded_folder_is_refused_at_any_depth(target):
    assert repo_path_reason(target, EXCLUDED) == "Path excluded from the review"


@pytest.mark.parametrize(
    "target",
    [
        "app/main.py",
        "app/secrets.py",
        "app/config/keys.py",
        "my-secrets/x",
        "config/x/keys",
        "app/.github/workflows/ci.yml",
    ],
)
def test_paths_next_to_an_excluded_folder_stay_in_scope(target):
    assert repo_path_reason(target, EXCLUDED) == ""


@pytest.mark.parametrize(
    "target",
    [
        "app/%2e%2e/%2e%2e/etc/passwd",
        "%2e%2e/x",
        "app%2f..%2fx",
        "app/%2E%2E/x",
        "a%5cb",
        "%7e/.ssh/id_rsa",
    ],
)
def test_percent_encoded_traversal_leaves_the_repository(target):
    assert repo_path_reason(target, []) == "Path leaves the repository"


def test_the_source_template_refuses_a_nested_excluded_folder():
    store.start_run("review repo https://git.example.com/acme/app.git")
    assert play_until_gate() == "scope"  # the repo picked Source Code; checked on the draft
    excluded = store.get_scope().excluded_paths
    assert repo_path_reason("app/main.py", excluded) == ""
    assert repo_path_reason("app/.git/config", excluded)
    assert repo_path_reason("app/secrets/prod.env", excluded)


# --- S6: LiteLLM uses its own price list, no download ---------------------------------------------
def test_the_local_price_list_is_chosen_before_litellm_is_imported():
    probe = textwrap.dedent("""
        import json, os, sys
        os.environ.pop("LITELLM_LOCAL_MODEL_COST_MAP", None)
        seen = []
        class Watch:
            def find_spec(self, name, path=None, target=None):
                if name == "litellm" and not seen:
                    seen.append(os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP"))
                return None
        sys.meta_path.insert(0, Watch())
        import reconix.llm.client  # noqa: F401
        print(json.dumps(seen))
    """)
    out = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parents[1],
        timeout=120,
        check=True,
    )
    assert json.loads(out.stdout.strip().splitlines()[-1]) == ["True"]
