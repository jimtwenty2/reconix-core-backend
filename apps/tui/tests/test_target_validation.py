"""validate_target(): one typed value read as a target kind, normalized, or a clear error."""

import os

import pytest

from reconix.store.targets import (
    MAX_RANGE_ADDRESSES,
    SUPPORTED_FORMATS,
    TARGET_KINDS,
    looks_like_target,
    validate_target,
)


@pytest.mark.parametrize(
    "text, kind, value",
    [
        # URL: http/https with a host; credentials and fragments are dropped
        ("https://app.example.com", "URL", "https://app.example.com"),
        (
            "HTTP://Shop.Example.com:8080/cart?id=1#top",
            "URL",
            "http://shop.example.com:8080/cart?id=1",
        ),
        ("https://user:pw@api.example.com/v1", "URL", "https://api.example.com/v1"),
        ("  https://192.0.2.10/  ", "URL", "https://192.0.2.10/"),
        # IPv4
        ("192.0.2.10", "IPV4", "192.0.2.10"),
        ("10.0.0.5", "IPV4", "10.0.0.5"),
        ("10.0.0.5/32", "IPV4", "10.0.0.5"),
        # IPv4 range: CIDR and dash ranges
        ("10.0.0.0/24", "IPV4_RANGE", "10.0.0.0/24"),
        ("10.0.0.5/24", "IPV4_RANGE", "10.0.0.0/24"),
        ("10.0.0.0/16", "IPV4_RANGE", "10.0.0.0/16"),
        ("10.0.0.1-10.0.0.20", "IPV4_RANGE", "10.0.0.1-10.0.0.20"),
        ("10.0.0.1-20", "IPV4_RANGE", "10.0.0.1-10.0.0.20"),
        ("10.0.0.7-10.0.0.7", "IPV4_RANGE", "10.0.0.7-10.0.0.7"),
        ("10.0.0.0-10.0.255.255", "IPV4_RANGE", "10.0.0.0-10.0.255.255"),  # exactly /16
        # Git repo
        ("https://github.com/acme/app", "GIT_REPO", "https://github.com/acme/app"),
        (
            "https://git.example.com/acme/app.git",
            "GIT_REPO",
            "https://git.example.com/acme/app.git",
        ),
        ("git@github.com:acme/app.git", "GIT_REPO", "git@github.com:acme/app.git"),
        (
            "ssh://git@git.example.com/acme/app.git",
            "GIT_REPO",
            "ssh://git.example.com/acme/app.git",
        ),
        ("github.com/acme/app", "GIT_REPO", "github.com/acme/app"),
    ],
)
def test_valid_targets_are_read_and_normalized(text, kind, value):
    check = validate_target(text)
    assert (check.kind, check.value, check.error) == (kind, value, "")
    assert check.valid and check.kind in TARGET_KINDS


@pytest.mark.parametrize(
    "text, says",
    [
        # empty
        ("", "Type a target"),
        (" ", "Type a target"),
        ("\t\n  ", "Type a target"),
        # URL
        ("http://", "has no host name"),
        ("https://:8080/x", "has no host name"),
        ("ftp://files.example.com", "ftp: links aren't supported"),
        ("file:///etc/passwd", "file: links aren't supported"),
        ("javascript:alert(1)", "javascript: links aren't supported"),
        ("https://app.example.com:99999", "invalid port"),
        # IPv4
        ("256.0.0.1", "isn't a valid IPv4 address"),
        ("999.1.1.1", "isn't a valid IPv4 address"),
        ("10.0.0", "isn't a valid IPv4 address"),
        ("x10.0.0.1", "isn't a target"),
        ("0.0.0.0", "can be tested"),
        # IPv4 range
        ("10.0.0.0/8", "too wide"),
        ("10.0.0.0/40", "isn't a valid IPv4 range"),
        ("10.0.0.5-10.0.0.1", "runs backwards"),
        ("10.0.0.1-300", "isn't a valid IPv4 address"),
        ("10.0.0.0-10.1.0.0", f"the limit is {MAX_RANGE_ADDRESSES:,}"),
        # Git repo
        ("git@github.com", "isn't a repository"),
        ("github.com/acme", "isn't a repository"),
        ("https://github.com", "isn't a repository"),
        # Local path
        ("/does/not/exist", "doesn't exist"),
        ("~/no-such-folder-reconix-test", "doesn't exist"),
        ("./no-such-folder-reconix-test", "doesn't exist"),
        # anything else
        ("hello", "isn't a target"),
        ("scan 10.0.0.1", "without spaces"),
    ],
)
def test_invalid_targets_say_what_is_wrong(text, says):
    check = validate_target(text)
    assert check.kind == "INVALID" and not check.valid and check.value == ""
    assert says in check.error
    assert "\n" not in check.error  # one line


def test_anything_unknown_lists_every_supported_format():
    error = validate_target("not-a-target").error
    assert error.endswith(SUPPORTED_FORMATS)
    for example in ("https://", "192.0.2.10", "10.0.0.0/24", "git@", "~/code/app"):
        assert example in error


def test_an_existing_folder_is_a_local_path(tmp_path):
    check = validate_target(str(tmp_path))
    assert (check.kind, check.value) == ("LOCAL_PATH", os.path.abspath(str(tmp_path)))


def test_home_is_expanded():
    check = validate_target("~")
    assert (check.kind, check.value) == ("LOCAL_PATH", os.path.expanduser("~"))


def test_a_relative_folder_becomes_absolute(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    monkeypatch.chdir(tmp_path)
    check = validate_target("./app")
    assert (check.kind, check.value) == ("LOCAL_PATH", str(tmp_path / "app"))


def test_a_file_is_not_a_folder(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("x", encoding="utf-8")
    check = validate_target(str(path))
    assert check.kind == "INVALID" and "is a file" in check.error


def test_a_long_value_is_shortened_in_the_message():
    error = validate_target("/" + "a" * 200).error
    assert len(error) < 120 and "…" in error


@pytest.mark.parametrize(
    "text, expected",
    [
        ("https://app.example.com", True),
        ("10.0.0.5", True),
        ("10.0.0.1-20", True),
        ("256.0.0.1", True),
        ("git@github.com:acme/app.git", True),
        ("github.com/acme", True),
        ("/does/not/exist", True),
        ("~/code", True),
        ("javascript:alert(1)", True),
        ("hello", False),
        ("what is 10.0.0.1?", False),  # a sentence goes to the chat
        ("staging.example.com", False),  # a bare host: the parser asks for the template
        ("3.14", False),
        ("", False),
    ],
)
def test_looks_like_target(text, expected):
    assert looks_like_target(text) is expected
