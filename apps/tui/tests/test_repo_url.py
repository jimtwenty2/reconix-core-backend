"""A repo source target always reaches the backend as https://github.com/<owner>/<repo>."""

import re

import pytest

from reconix import store
from reconix.store import targets

# services/api/src/reconix_api/services/code.py GITHUB_URL, used with fullmatch
BACKEND_GITHUB_URL = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?")

ACCEPTED = [
    ("https://github.com/acme/app", "https://github.com/acme/app"),
    ("https://github.com/acme/app/", "https://github.com/acme/app"),
    ("https://github.com/acme/app.git", "https://github.com/acme/app"),
    ("https://github.com/acme/app/tree/main", "https://github.com/acme/app"),
    ("https://github.com/acme/app/blob/main/x.py", "https://github.com/acme/app"),
    ("https://github.com/acme/app?x=1", "https://github.com/acme/app"),
    ("https://github.com/acme/app#readme", "https://github.com/acme/app"),
    ("http://github.com/acme/app", "https://github.com/acme/app"),
    ("https://www.github.com/acme/app", "https://github.com/acme/app"),
    ("https://bot:ghp_fake@github.com/acme/app", "https://github.com/acme/app"),
    ("https://GitHub.com/Acme/My.App", "https://github.com/Acme/My.App"),
    ("git@github.com:acme/app.git", "https://github.com/acme/app"),
    ("ssh://git@github.com/acme/app.git", "https://github.com/acme/app"),
    ("github.com/acme/app", "https://github.com/acme/app"),
    ("www.github.com/acme/app", "https://github.com/acme/app"),
]
NOT_GITHUB = [
    "https://gitlab.com/acme/app",
    "https://bitbucket.org/acme/app",
    "gitlab.com/acme/app",
    "git@gitlab.com:acme/app.git",
    "ssh://git@git.example.com/acme/app.git",
    "https://git.example.com/acme/app.git",
]
NOT_A_REPO = ["github.com/acme", "https://github.com/acme", "git@github.com:acme"]


@pytest.mark.parametrize("typed, canonical", ACCEPTED)
def test_every_github_form_is_canonical_and_passes_the_backend(typed, canonical):
    for value in (
        targets.github_repo(typed),
        store.check_target("source", typed).target_url,
        store.check_target("source", f"review {typed} please").target_url,
        targets.validate_target(typed).value,
    ):
        assert value == canonical
        assert BACKEND_GITHUB_URL.fullmatch(value)


@pytest.mark.parametrize("typed", NOT_GITHUB)
def test_other_hosts_are_refused_github_only(typed):
    with pytest.raises(store.StoreValidationError, match="Only GitHub repos are supported"):
        store.check_target("source", typed)
    check = targets.validate_target(typed)
    assert not check.valid and "Only GitHub" in check.error


@pytest.mark.parametrize("typed", NOT_A_REPO)
def test_github_without_owner_and_repo_is_not_a_repository(typed):
    with pytest.raises(store.StoreValidationError, match="isn't a repository"):
        store.check_target("source", typed)


@pytest.mark.parametrize("typed", ["/home/me/app", "./app", "../app", "~/code/app"])
def test_local_paths_are_left_untouched(typed):
    assert store.check_target("source", typed).target_url == typed


def test_an_ordinary_site_is_not_a_repo():
    assert targets.source_target("review https://shop.example.com") is None
    assert targets.validate_target("https://shop.example.com").kind == "URL"
