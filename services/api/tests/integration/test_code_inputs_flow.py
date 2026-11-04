"""Code from a folder on this computer, a local clone, or git clone, through the API and a
real database. git clones a local file:// repo through the test seam, so no network is used."""

import base64
import logging
import subprocess
from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy
from sqlalchemy.exc import OperationalError

from reconix_api.core.config import get_settings
from reconix_api.services import code
from tests.integration.test_code_scan_flow import (
    code_assessment,
    send_code,
    slow_tools,
    start,
    tool_outputs,
    vscode_session,
    wait_for_end,
)

TOKEN = "ghp_FAKEtokenFAKEtokenFAKEtokenFAKE0000"  # noqa: S105 - a fake token
URL = "https://github.com/DansPK/vuln-lab"


@pytest.fixture
def client(code_client):
    return code_client


@pytest.fixture
def src(tmp_path_factory) -> Path:
    """A project outside the code folder: files to keep, and files to leave out."""
    root = tmp_path_factory.mktemp("projects") / "lab"
    for name, text in {
        "src/app.js": "const out = eval(req.query.code);\n",
        "config.js": "module.exports = { key: 'not-a-real-key' };\n",
        ".semgrepignore": "*\n",
        "node_modules/m/index.js": "x\n",
        ".git/config": '[remote "origin"]\n\turl = git@github.com:DansPK/vuln-lab.git\n',
    }.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    (root / "link.js").symlink_to(root / "config.js")
    return root


def stored(code_dir: Path, session_id: str) -> list[str]:
    folder = code_dir / session_id
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())


def audited(db_app, event_type: str) -> list[dict]:
    events = db_app.state.parts["audit"].events
    return [event.details for event in events if event.event_type == event_type]


def use_settings(db_app, **changes) -> None:
    settings = db_app.dependency_overrides[get_settings]()
    changed = settings.model_copy(update=changes)
    db_app.dependency_overrides[get_settings] = lambda: changed


def test_a_folder_replaces_the_session_code_without_links_git_or_packages(
    client, db_app, code_dir, src
):
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, {"old.py": b"print(1)\n"})

    copied = client.post(
        f"/sessions/{session_id}/code/folder", json={"path": str(src)}, headers=headers
    )

    assert copied.status_code == 200, copied.json()
    assert copied.json() == {
        "files": 2,
        "size_bytes": 78,
        "target": f"/workspace/code/{session_id}",
    }
    assert stored(code_dir, session_id) == ["config.js", "src/app.js"]
    assert (src / ".git" / "config").exists()  # the folder itself is never changed
    assert audited(db_app, "CODE_COPIED") == [{"path": str(src.resolve()), "files": 2}]


def test_a_folder_with_secrets_or_of_another_session_is_refused(
    client, code_dir, tmp_path_factory, monkeypatch
):
    home = tmp_path_factory.mktemp("home")
    (home / ".ssh").mkdir()
    monkeypatch.setenv("HOME", str(home))
    headers, session_id = vscode_session(client)
    _, other = vscode_session(client)

    def copy(path: str, session: str = session_id):
        return client.post(f"/sessions/{session}/code/folder", json={"path": path}, headers=headers)

    assert copy(str(home / ".ssh")).json()["code"] == "FOLDER_NOT_ALLOWED"
    assert copy(str(code_dir)).json()["code"] == "FOLDER_NOT_ALLOWED"
    assert copy("/no/such/folder").json()["code"] == "FOLDER_NOT_FOUND"
    assert copy(str(home), other).json()["code"] == "NOT_YOUR_SESSION"


def test_a_local_clone_is_copied_and_never_pulled(client, db_app, code_dir, src):
    use_settings(db_app, local_repo_roots=[str(src.parent)])
    headers, session_id = vscode_session(client)

    cloned = client.post(
        f"/sessions/{session_id}/code/clone", json={"url": f"{URL}.git"}, headers=headers
    )

    assert cloned.status_code == 200, cloned.json()
    assert cloned.json()["source"] == "LOCAL_CLONE"
    assert stored(code_dir, session_id) == ["config.js", "src/app.js"]
    assert audited(db_app, "CODE_CLONED") == [
        {"url": f"{URL}.git", "source": "LOCAL_CLONE", "files": 2}
    ]


def git_repo(folder: Path) -> Path:
    folder.mkdir()
    (folder / "app.py").write_text("import os\nos.system(input())\n")
    (folder / "lib").mkdir()
    (folder / "lib" / "util.py").write_text("X = 1\n")
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(folder)}
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(folder)]
    for args in (["init", "-q"], ["add", "."], ["commit", "-qm", "one"]):
        subprocess.run([*git, *args], check=True, env=env)  # noqa: S603
    return folder


def test_git_clone_with_a_token_never_shows_it(
    client, db_app, code_dir, tmp_path_factory, monkeypatch, caplog
):
    caplog.set_level(logging.DEBUG)
    repo = git_repo(tmp_path_factory.mktemp("remote") / "lab")
    monkeypatch.setattr(code, "clone_source", lambda _: ("file", f"file://{repo}"))
    headers, session_id = vscode_session(client)

    cloned = client.post(
        f"/sessions/{session_id}/code/clone", json={"url": URL, "token": TOKEN}, headers=headers
    )

    assert cloned.status_code == 200, cloned.json()
    assert cloned.json()["source"] == "GITHUB"
    assert stored(code_dir, session_id) == ["app.py", "lib/util.py"]  # no .git
    assert audited(db_app, "CODE_CLONED") == [{"url": URL, "source": "GITHUB", "files": 2}]
    basic = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    shown = f"{cloned.text} {caplog.text} {db_app.state.parts['audit'].events}"
    assert TOKEN not in shown and basic not in shown


@pytest.mark.parametrize(
    "url", ["https://gitlab.com/a/b", "file:///etc", "https://x:y@github.com/a/b", "ext::sh"]
)
def test_only_github_urls_can_be_cloned(client, url):
    headers, session_id = vscode_session(client)
    cloned = client.post(f"/sessions/{session_id}/code/clone", json={"url": url}, headers=headers)
    assert cloned.status_code == 422
    assert cloned.json()["code"] == "INVALID_REPO_URL"


def test_a_failed_clone_changes_nothing(client, code_dir, tmp_path_factory, monkeypatch):
    missing = tmp_path_factory.mktemp("remote") / "missing"
    monkeypatch.setattr(code, "clone_source", lambda _: ("file", f"file://{missing}"))
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, {"old.py": b"print(1)\n"})

    cloned = client.post(
        f"/sessions/{session_id}/code/clone", json={"url": URL, "token": TOKEN}, headers=headers
    )

    assert cloned.status_code == 502
    assert cloned.json()["code"] == "CLONE_FAILED"
    assert TOKEN not in cloned.text
    assert stored(code_dir, session_id) == ["old.py"]


def test_copied_code_can_be_scanned_and_cannot_change_during_a_scan(client, db_app, src):
    headers, session_id = vscode_session(client)
    copied = client.post(
        f"/sessions/{session_id}/code/folder", json={"path": str(src)}, headers=headers
    )
    target = copied.json()["target"]
    tool_outputs(db_app, target)
    assessment_id = code_assessment(client, headers, target)
    slow_tools(db_app, 0.3)

    scan = start(client, headers, assessment_id).json()
    again = client.post(
        f"/sessions/{session_id}/code/folder", json={"path": str(src)}, headers=headers
    )

    assert again.status_code == 409
    assert again.json()["code"] == "SCAN_RUNNING"
    done = wait_for_end(client, headers, scan["agent_run_id"])
    assert done["agent_runs_status"] == "COMPLETED"
    assert done["counts"]["HIGH"] == 2


def test_a_folder_that_cannot_be_stored_keeps_the_old_code(client, db_app, code_dir, src):
    headers, session_id = vscode_session(client)
    send_code(client, headers, session_id, {"old.py": b"print(1)\n"})
    (src / "bad:name.js").write_text("x\n")  # packed, but unpack refuses the name

    copied = client.post(
        f"/sessions/{session_id}/code/folder", json={"path": str(src)}, headers=headers
    )

    assert copied.status_code == 422
    assert copied.json()["code"] == "INVALID_CODE_FOLDER"
    assert stored(code_dir, session_id) == ["old.py"]
    assert not (code_dir / f".{session_id}.new").exists()


def test_a_local_clone_that_holds_secrets_is_cloned_from_github_instead(
    client, db_app, code_dir, tmp_path_factory, monkeypatch
):
    """A dotfiles repo at ~ holds ~/.ssh: it is never copied as it is."""
    home = tmp_path_factory.mktemp("home")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("not a real key\n")
    (home / ".git").mkdir()
    (home / ".git" / "config").write_text(f'[remote "origin"]\n\turl = {URL}\n')
    monkeypatch.setenv("HOME", str(home))
    use_settings(db_app, local_repo_roots=[str(home)])
    repo = git_repo(tmp_path_factory.mktemp("remote") / "lab")
    monkeypatch.setattr(code, "clone_source", lambda _: ("file", f"file://{repo}"))
    headers, session_id = vscode_session(client)

    cloned = client.post(f"/sessions/{session_id}/code/clone", json={"url": URL}, headers=headers)

    assert cloned.status_code == 200, cloned.json()
    assert cloned.json()["source"] == "GITHUB"
    assert stored(code_dir, session_id) == ["app.py", "lib/util.py"]


def test_changing_code_holds_the_session_row_so_no_first_scan_starts(client, session_factory):
    """With no assessment yet there is no assessment row to lock: the session row is."""
    headers, session_id = vscode_session(client)
    with session_factory() as db, session_factory() as other:
        code.ensure_not_scanning(db, UUID(session_id))
        with pytest.raises(OperationalError):  # NOWAIT: the row is taken
            other.execute(
                sqlalchemy.text("SELECT 1 FROM sessions WHERE session_id = :id FOR UPDATE NOWAIT"),
                {"id": session_id},
            )
        db.rollback()
