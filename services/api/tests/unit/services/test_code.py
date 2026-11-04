"""Code inputs: the GitHub URL check, finding a local clone, the folder deny list, and git
clone with a token that never reaches git's command line, a log or an error."""

import base64
import logging
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr

from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import AuditEvent, Operator
from reconix_api.services import code

TOKEN = "ghp_FAKEtokenFAKEtokenFAKEtokenFAKE0000"  # noqa: S105 - a fake token


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/DansPK/vuln-lab",
        "https://github.com/DansPK/vuln-lab.git",
        "https://github.com/DansPK/vuln-lab/",
        "https://github.com/a_b/c.d-e",
    ],
)
def test_github_urls_are_accepted(url):
    assert code.GITHUB_URL.fullmatch(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://gitlab.com/a/b",
        "https://github.com.evil.com/a/b",
        "https://x:y@github.com/a/b",
        "https://github.com/a",
        "https://github.com/a/b/tree/main",
        "https://github.com/a/b?x=1",
        "git@github.com:a/b.git",
        "file:///tmp/repo",
        "https://github.com/a/b\n",
        "--upload-pack=x",
    ],
)
def test_other_urls_are_refused(url):
    assert not code.GITHUB_URL.fullmatch(url)


@pytest.mark.parametrize(
    "remote",
    [
        "https://github.com/DansPK/vuln-lab",
        "https://github.com/dansPK/Vuln-Lab.git",
        "https://user@github.com/DansPK/vuln-lab/",
        "git@github.com:DansPK/vuln-lab.git",
        "ssh://git@github.com/DansPK/vuln-lab.git",
        "  git@github.com:DansPK/vuln-lab  ",
    ],
)
def test_every_remote_form_names_the_same_repo(remote):
    assert code.repo_key(remote) == "danspk/vuln-lab"


@pytest.mark.parametrize("remote", ["https://gitlab.com/a/b", "/srv/repos/b.git", ""])
def test_other_remotes_name_no_github_repo(remote):
    assert code.repo_key(remote) is None


def git_repo(folder: Path, origin: str, other: str = "https://github.com/x/fork") -> Path:
    """A folder with a hand-written .git/config: no git needed."""
    (folder / ".git").mkdir(parents=True)
    (folder / ".git" / "config").write_text(
        "[core]\n\tbare = false\n"
        f'[remote "upstream"]\n\turl = {other}\n'
        f'[remote "origin"]\n\turl = {origin}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
    )
    return folder


def test_origin_url_is_read_from_the_config_text(tmp_path):
    repo = git_repo(tmp_path / "r", "git@github.com:a/b.git")
    assert code.origin_url(repo / ".git" / "config") == "git@github.com:a/b.git"
    assert code.origin_url(tmp_path / "missing") is None


def test_a_local_clone_is_found_by_its_origin(tmp_path):
    git_repo(tmp_path / "a" / "fork", "https://github.com/x/other", other="https://github.com/a/b")
    wanted = git_repo(tmp_path / "b" / "lab", "git@github.com:DansPK/vuln-lab.git")
    key = "danspk/vuln-lab"
    assert code.find_local_clone([str(tmp_path)], key, []) == wanted.resolve()
    assert code.find_local_clone([str(tmp_path / "a")], key, []) is None  # upstream ignored
    assert code.find_local_clone([str(tmp_path / "none")], key, []) is None


def test_the_local_clone_search_has_limits(tmp_path):
    key = "a/b"
    git_repo(tmp_path / "1" / "2" / "3" / "4" / "5", "https://github.com/a/b")  # too deep
    git_repo(tmp_path / "node_modules" / "b", "https://github.com/a/b")
    git_repo(tmp_path / "data" / "code" / "b", "https://github.com/a/b")
    git_repo(tmp_path / "outer", "https://github.com/x/y")
    git_repo(tmp_path / "outer" / "inner", "https://github.com/a/b")  # inside another repo
    (tmp_path / "link").symlink_to(tmp_path / "1" / "2" / "3" / "4" / "5")
    assert code.find_local_clone([str(tmp_path)], key, [tmp_path / "data" / "code"]) is None
    found = git_repo(tmp_path / "1" / "2" / "3" / "4b", "https://github.com/a/b")
    assert code.find_local_clone([str(tmp_path)], key, []) == found.resolve()


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_ed25519").write_text("not a real key")
    (home / "projects" / "app").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    return home


AUDIT: list[AuditEvent] = []


def copy(settings: Settings, path: str):
    operator = Operator(session_id=uuid4(), actor="t")
    return code.copy_folder(None, AUDIT.append, settings, operator, uuid4(), path)  # type: ignore[arg-type]


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Settings:
    # Only the deny list is tested here, so the session check is skipped.
    monkeypatch.setattr(code, "ensure_own_open_session", lambda *_: None)
    return Settings(_env_file=None, code_dir=str(tmp_path / "data" / "code"))


@pytest.mark.parametrize(
    "path",
    [
        "~/.ssh",
        "~/.ssh/../.ssh",
        "~",  # holds ~/.ssh
        "/",
        "/etc",
        "/proc/self",
        "/var/log",
        "/run",
        "~/.config/gcloud",
        "~/.claude",
    ],
)
def test_folders_with_secrets_or_system_files_are_refused(home, settings, path):
    for name in (".config/gcloud", ".claude"):
        (home / name).mkdir(parents=True, exist_ok=True)
    AUDIT.clear()
    with pytest.raises(ApiError) as error:
        copy(settings, path)
    assert error.value.code == "FOLDER_NOT_ALLOWED"
    # One audit line for the refusal, with no path in it.
    assert [(event.event_type, event.details) for event in AUDIT] == [
        ("CODE_FOLDER_REFUSED", {"code": "FOLDER_NOT_ALLOWED"})
    ]


def test_a_link_into_ssh_is_refused(home, settings, tmp_path):
    (tmp_path / "innocent").symlink_to(home / ".ssh")
    with pytest.raises(ApiError) as error:
        copy(settings, str(tmp_path / "innocent"))
    assert error.value.code == "FOLDER_NOT_ALLOWED"


@pytest.mark.parametrize("inside", ["data/code/s", "data"])
def test_reconix_own_folders_and_its_repo_are_refused(home, settings, tmp_path, inside):
    """Inside the code folder, or holding it: Reconix's own repo, whose .env has its keys."""
    (tmp_path / "data" / "code" / "s").mkdir(parents=True)
    with pytest.raises(ApiError) as error:
        copy(settings, str(tmp_path / inside))
    assert error.value.code == "FOLDER_NOT_ALLOWED"
    assert "Reconix's own data" in error.value.message


@pytest.mark.parametrize("path", ["relative/app", "/no/such/folder", "~/.ssh/id_ed25519"])
def test_a_missing_or_relative_folder_or_a_file_is_refused(home, settings, path):
    with pytest.raises(ApiError) as error:
        copy(settings, path)
    assert error.value.code == "FOLDER_NOT_FOUND"


def test_a_project_folder_is_allowed(home, settings):
    code.ensure_folder_allowed((home / "projects" / "app").resolve(), settings)


@pytest.fixture
def git_run(monkeypatch):
    """Records git's command and environment instead of running it."""
    calls: list[dict] = []

    def run(command, **options):
        calls.append({"command": command, **options})
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(code.shutil, "which", lambda _: "/usr/bin/git")
    monkeypatch.setattr(code.subprocess, "run", run)
    return calls


def test_git_clone_is_shallow_and_https_only(git_run, tmp_path):
    code.git_clone("https://github.com/a/b", tmp_path / "repo", None)
    (call,) = git_run
    assert call["command"] == [
        "/usr/bin/git",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.symlinks=false",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--",
        "https://github.com/a/b",
        str(tmp_path / "repo"),
    ]
    assert call["timeout"] == code.CLONE_SECONDS
    assert call["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert call["env"]["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert (call["env"]["GIT_ASKPASS"], call["env"]["SSH_ASKPASS"]) == ("", "")  # no prompt
    assert "GIT_CONFIG_VALUE_0" not in call["env"]  # this computer's credentials apply


def test_reconix_settings_never_reach_git(git_run, tmp_path, monkeypatch):
    monkeypatch.setenv("RECONIX_FERNET_KEY", "fernet-key-value")
    monkeypatch.setenv("PATH", "/usr/bin")
    code.git_clone("https://github.com/a/b", tmp_path / "repo", SecretStr(TOKEN))
    (call,) = git_run
    assert not any(name.startswith("RECONIX_") for name in call["env"])
    assert call["env"]["PATH"] == "/usr/bin"


def test_a_token_goes_only_into_git_s_environment(git_run, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    code.git_clone("https://github.com/a/b", tmp_path / "repo", SecretStr(TOKEN))
    (call,) = git_run
    assert not any(TOKEN in part for part in call["command"])
    basic = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    env = call["env"]
    assert env["GIT_CONFIG_COUNT"] == "2"
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {basic}"
    assert (env["GIT_CONFIG_KEY_1"], env["GIT_CONFIG_VALUE_1"]) == ("credential.helper", "")
    assert TOKEN not in caplog.text and basic not in caplog.text


def test_a_failed_clone_never_shows_the_token(monkeypatch, tmp_path, caplog):
    def run(command, **options):
        stderr = options["env"]["GIT_CONFIG_VALUE_0"].encode()  # even if git echoed it
        return subprocess.CompletedProcess(command, 128, b"", stderr)

    monkeypatch.setattr(code.subprocess, "run", run)
    with pytest.raises(ApiError) as error:
        code.git_clone("https://github.com/a/b", tmp_path / "repo", SecretStr(TOKEN))
    assert error.value.code == "CLONE_FAILED"
    basic = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    shown = f"{error.value.message} {error.value.details} {caplog.text}"
    assert TOKEN not in shown and basic not in shown


def test_a_slow_clone_times_out_and_no_git_is_a_clear_error(monkeypatch, tmp_path):
    def slow(command, **options):
        raise subprocess.TimeoutExpired(command, options["timeout"])

    monkeypatch.setattr(code.subprocess, "run", slow)
    with pytest.raises(ApiError) as error:
        code.git_clone("https://github.com/a/b", tmp_path / "repo", None)
    assert error.value.code == "CLONE_TIMED_OUT"
    monkeypatch.setattr(code.shutil, "which", lambda _: None)
    with pytest.raises(ApiError) as error:
        code.git_clone("https://github.com/a/b", tmp_path / "repo", None)
    assert error.value.code == "GIT_NOT_FOUND"


def make_repo(folder: Path) -> Path:
    folder.mkdir()
    (folder / "app.py").write_text("print('hi')\n")
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(folder)}
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(folder)]
    for args in (["init", "-q"], ["add", "."], ["commit", "-qm", "one"]):
        subprocess.run([*git, *args], check=True, env=env)  # noqa: S603
    return folder


def test_git_may_use_no_protocol_but_the_allowed_one(monkeypatch, tmp_path):
    """Real git: a file:// address is refused while only https is allowed, and works
    once the test seam allows file."""
    repo = make_repo(tmp_path / "origin")
    monkeypatch.setattr(code, "clone_source", lambda _: ("https", f"file://{repo}"))
    with pytest.raises(ApiError) as error:
        code.git_clone("https://github.com/a/b", tmp_path / "one", None)
    assert error.value.code == "CLONE_FAILED"
    monkeypatch.setattr(code, "clone_source", lambda _: ("file", f"file://{repo}"))
    code.git_clone("https://github.com/a/b", tmp_path / "two", None)
    assert (tmp_path / "two" / "app.py").read_text() == "print('hi')\n"
