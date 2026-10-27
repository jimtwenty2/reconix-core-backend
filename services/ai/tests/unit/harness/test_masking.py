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
        "headers": {"Authorization": "Bearer [MASKED:token]"},
        "count": 3,
        "pair": ("token=[MASKED:token]", None),
    }
    assert count == 3
