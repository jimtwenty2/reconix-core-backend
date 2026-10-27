import pytest

from reconix_ai.harness.masking import mask_secrets, mask_value

# Fake secrets, built from parts so secret scanners do not flag this file.
GITHUB_TOKEN = "ghp_" + "a1B2" * 9
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
GOOGLE_KEY = "AIza" + "x" * 35
OPENAI_KEY = "sk-" + "proj" + "Q" * 24
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjMifQ" + ".c2lnbmF0dXJl"
PRIVATE_KEY = (
    "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA " + "PRIVATE KEY-----"
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=hunter22", "password=[MASKED:password]"),
        ("PASSWORD: hunter22 next", "PASSWORD: [MASKED:password] next"),
        ('{"password": "hunter 22"}', '{"password": "[MASKED:password]"}'),
        ("pwd='s3cr3t!'", "pwd='[MASKED:password]'"),
        (
            "login?user=bob&pass=hunter22&x=1",
            "login?user=bob&pass=[MASKED:password]&x=1",
        ),
        (
            "http://bob:hunter22@juice-shop.lab/",
            "http://bob:[MASKED:password]@juice-shop.lab/",
        ),
    ],
)
def test_passwords_are_masked(text: str, expected: str) -> None:
    assert mask_secrets(text) == (expected, 1)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Authorization: Bearer abcdef123456", "Authorization: Bearer [MASKED:token]"),
        ("token=abc123xyz", "token=[MASKED:token]"),
        ('"access_token": "abc.def"', '"access_token": "[MASKED:token]"'),
        ("session_id=9f8e7d6c", "session_id=[MASKED:token]"),
        (f"cookie {JWT} end", "cookie [MASKED:token] end"),
        (f"token is {GITHUB_TOKEN}", "token is [MASKED:token]"),
    ],
)
def test_tokens_are_masked(text: str, expected: str) -> None:
    assert mask_secrets(text) == (expected, 1)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"key {AWS_KEY}", "key [MASKED:api_key]"),
        (f"key {GOOGLE_KEY}", "key [MASKED:api_key]"),
        (f"OPENAI={OPENAI_KEY}", "OPENAI=[MASKED:api_key]"),
        ("api_key=abcd1234", "api_key=[MASKED:api_key]"),
        ('client_secret: "xyz789"', 'client_secret: "[MASKED:api_key]"'),
    ],
)
def test_api_keys_are_masked(text: str, expected: str) -> None:
    assert mask_secrets(text) == (expected, 1)


def test_private_key_block_is_masked() -> None:
    assert mask_secrets(f"found:\n{PRIVATE_KEY}\ndone") == (
        "found:\n[MASKED:private_key]\ndone",
        1,
    )


def test_bearer_jwt_is_masked_once() -> None:
    assert mask_secrets(f"Authorization: Bearer {JWT}") == (
        "Authorization: Bearer [MASKED:token]",
        1,
    )


def test_every_secret_is_counted() -> None:
    text = f"password=a1 token=b2 {AWS_KEY}"
    masked, count = mask_secrets(text)
    assert masked == "password=[MASKED:password] token=[MASKED:token] [MASKED:api_key]"
    assert count == 3


def test_masking_twice_changes_nothing() -> None:
    once, _ = mask_secrets("password=hunter22 token=abc123")
    assert mask_secrets(once) == (once, 0)


@pytest.mark.parametrize(
    "text",
    [
        "Scan 172.20.0.5 for open ports",
        "22/tcp open ssh OpenSSH 8.9",
        "The password field has no rate limit",
        "Reset your password at /reset",
        "tokens are rotated every hour",
        "",
    ],
)
def test_normal_text_is_unchanged(text: str) -> None:
    assert mask_secrets(text) == (text, 0)


def test_mask_value_masks_nested_details() -> None:
    details = {
        "target": "172.20.0.5",
        "arguments": ["-p", "80", "--auth", "password=hunter22"],
        "headers": {"Authorization": "Bearer abcdef123456"},
        "count": 3,
        "pair": ("token=abc123", None),
    }
    masked, count = mask_value(details)
    assert masked == {
        "target": "172.20.0.5",
        "arguments": ["-p", "80", "--auth", "password=[MASKED:password]"],
        "headers": {"Authorization": "[MASKED:token]"},
        "count": 3,
        "pair": ("token=[MASKED:token]", None),
    }
    assert count == 3


# --- shapes the first version missed ---------------------------------------

STRIPE_KEY = "sk_" + "live_" + "Z" * 24
AWS_TEMP_KEY = "ASIA" + "ABCDEFGHIJKLMNOP"
GITLAB_TOKEN = "glpat-" + "x1Y2" * 5


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # a prefix before the key name
        ("DB_PASSWORD=hunter2", "DB_PASSWORD=[MASKED:password]"),
        ("PGPASSWORD=hunter2", "PGPASSWORD=[MASKED:password]"),
        ("MYSQL_ROOT_PASSWORD: hunter2", "MYSQL_ROOT_PASSWORD: [MASKED:password]"),
        ("AWS_SECRET_ACCESS_KEY=wJalrXUtnF", "AWS_SECRET_ACCESS_KEY=[MASKED:api_key]"),
        ("GITHUB_TOKEN=abcd1234efgh5678", "GITHUB_TOKEN=[MASKED:token]"),
        ("JSESSIONID=9f8e7d6c5b", "JSESSIONID=[MASKED:token]"),
        ("PHPSESSID=9f8e7d6c5b", "PHPSESSID=[MASKED:token]"),
        # the other quote inside a quoted value
        ("""password="hun'ter2\"""", """password="[MASKED:password]\""""),
        ("""passwd: 'x"y'""", """passwd: '[MASKED:password]'"""),
        # "@" inside a URL password
        (
            "http://admin:p@ss@word@juice-shop.lab/",
            "http://admin:[MASKED:password]@juice-shop.lab/",
        ),
        # XML tags
        ("<password>hunter2</password>", "<password>[MASKED:password]</password>"),
        ("<apiKey>abcd1234</apiKey>", "<apiKey>[MASKED:token]</apiKey>"),
        # key formats
        (f"key {STRIPE_KEY}", "key [MASKED:api_key]"),
        (f"key {AWS_TEMP_KEY}", "key [MASKED:api_key]"),
        (f"key {GITLAB_TOKEN}", "key [MASKED:token]"),
        # cookie headers
        ("Cookie: session=abc; theme=dark", "Cookie: [MASKED:token]"),
        ("set-cookie: sid=abc123; HttpOnly", "set-cookie: [MASKED:token]"),
    ],
)
def test_more_secret_shapes_are_masked(text: str, expected: str) -> None:
    assert mask_secrets(text) == (expected, 1)


def test_cut_off_private_key_is_masked_to_the_end() -> None:
    text = "found:\n-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\nIBAAK"
    assert mask_secrets(text) == ("found:\n[MASKED:private_key]", 1)


def test_pgp_private_key_block_is_masked() -> None:
    text = (
        "-----BEGIN PGP "
        + "PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP "
        + "PRIVATE KEY BLOCK-----"
    )
    assert mask_secrets(text) == ("[MASKED:private_key]", 1)


def test_normal_words_with_pass_are_unchanged() -> None:
    text = "Scan passed: 3 hosts, compass heading north"
    assert mask_secrets(text) == (text, 0)


# --- mask_value: key names and other types ---------------------------------


def test_secret_key_names_mask_the_whole_value() -> None:
    details = {"password": "hunter2", "api_key": "abcd1234", "token": "tok123", "DB_PASS": "x"}
    masked, count = mask_value(details)
    assert masked == {
        "password": "[MASKED:password]",
        "api_key": "[MASKED:api_key]",
        "token": "[MASKED:token]",
        "DB_PASS": "[MASKED:password]",
    }
    assert count == 4


def test_secret_key_with_a_non_text_value_keeps_it() -> None:
    assert mask_value({"tokens_used": 120, "token": None}) == (
        {"tokens_used": 120, "token": None},
        0,
    )


def test_secret_inside_a_key_is_masked() -> None:
    # The key names a password, so its value is masked too.
    masked, count = mask_value({"password=hunter2": "x"})
    assert masked == {"password=[MASKED:password]": "[MASKED:password]"}
    assert count == 2


def test_bytes_and_sets_are_masked() -> None:
    masked, count = mask_value({"raw": b"token=abcdefgh", "tags": {"password=hunter2"}})
    assert masked == {"raw": "token=[MASKED:token]", "tags": ["password=[MASKED:password]"]}
    assert count == 2


def test_dataclasses_and_models_are_masked() -> None:
    from dataclasses import dataclass

    @dataclass
    class Command:
        cmd: str

    class Model:
        def model_dump(self, mode: str) -> dict:
            return {"cmd": "password=hunter2"}

    masked, count = mask_value({"a": Command("password=hunter2"), "b": Model()})
    assert masked == {
        "a": {"cmd": "password=[MASKED:password]"},
        "b": {"cmd": "password=[MASKED:password]"},
    }
    assert count == 2


def test_other_objects_become_masked_text() -> None:
    class Thing:
        def __str__(self) -> str:
            return "Thing(password=hunter2)"

    # A value with no quotes runs to the next space, so the ")" is masked too.
    assert mask_value(Thing()) == ("Thing(password=[MASKED:password]", 1)
