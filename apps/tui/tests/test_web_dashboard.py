"""/web starts the web dashboard when it isn't running (no `cd web && npm run dev`)."""

import json
import os
import socket
import sys
import time
from pathlib import Path

from reconix import browser, web_server
from reconix.browser import open_url as real_open_url      # before conftest stubs it
from reconix.shell import web as web_shell
from reconix.store import persist
from reconix.web_server import needs_install as real_needs_install
from reconix.web_server import problem as real_problem     # before conftest stubs it
from reconix.web_server import start as real_start

from .support import SIZE, settle

LINK = "http://127.0.0.1:3100/login#token=abc\n"


def _notes(app) -> str:
    return " ".join(str(n.message) for n in app._notifications)


async def test_the_first_web_starts_it_and_a_second_waits(app, opened, web_launches):
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        app.run_command_line("/web")                       # again, while it starts
        await settle(pilot)
        assert len(web_launches) == 1 and opened == []
        assert "Starting the web dashboard" in _notes(app)
        assert "still starting" in _notes(app)


async def test_it_says_when_it_is_ready(app, web_launches, monkeypatch):
    monkeypatch.setattr(web_shell, "POLL_EVERY", 0.01)
    monkeypatch.setattr(web_server, "is_listening", lambda url: bool(url))
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        persist.WEB_URL_FILE.write_text(LINK)              # what serve.mjs writes when ready
        await app.workers.wait_for_complete()
        await settle(pilot)
        assert "ready and opened in your browser" in _notes(app)
        assert not app._web_starting


async def test_it_says_when_another_dashboard_holds_the_port(app, web_launches, monkeypatch):
    class Busy:                                            # serve.mjs found its ports taken
        pid = -1

        def poll(self):
            return web_server.PORTS_BUSY

    monkeypatch.setattr(web_shell, "POLL_EVERY", 0.01)
    monkeypatch.setattr(web_server, "start", lambda data_dir, url_file: Busy())
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        await app.workers.wait_for_complete()
        await settle(pilot)
        assert "Another web dashboard already uses its port" in _notes(app)
        assert app._web_process is None and not app._web_starting


async def test_the_first_time_it_installs_the_packages_first(app, web_launches, monkeypatch):
    monkeypatch.setattr(web_server, "needs_install", lambda: True)
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        await settle(pilot)
        assert web_launches[0] == "install" and len(web_launches) == 2
        assert "packages are installed (or updated) first" in _notes(app)


async def test_without_node_it_says_what_to_install(app, web_launches, monkeypatch):
    monkeypatch.setattr(web_server, "problem", lambda: "The web dashboard needs Node.js.")
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        await settle(pilot)
        assert web_launches == []
        assert "Node.js" in _notes(app) and "npm run dev" not in _notes(app)


async def test_a_dashboard_it_started_stops_when_the_tui_quits(app, web_launches):
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        await settle(pilot)
        [dashboard] = web_launches
        assert not dashboard.stopped
    assert dashboard.stopped


def test_a_newly_added_package_triggers_an_install(monkeypatch, tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"next": "1", "gsap": "3"}}')
    (tmp_path / "node_modules" / "next").mkdir(parents=True)
    (tmp_path / "node_modules" / "next" / "package.json").write_text("{}")
    monkeypatch.setattr(web_server, "WEB_DIR", tmp_path)
    assert real_needs_install()                         # gsap is missing
    (tmp_path / "node_modules" / "gsap").mkdir(parents=True)
    (tmp_path / "node_modules" / "gsap" / "package.json").write_text("{}")
    assert not real_needs_install()


def test_its_log_is_private(monkeypatch, tmp_path):
    log = tmp_path / "web.log"
    log.write_text("old\n")
    log.chmod(0o644)                                     # from before: tightened
    monkeypatch.setattr(web_server, "LOG_FILE", log)
    with web_server._log() as out:
        out.write(b"new\n")
    assert (log.stat().st_mode & 0o777) == 0o600 and log.read_text() == "old\nnew\n"


def test_the_dashboard_runs_its_knowledge_cli_with_this_python(monkeypatch, tmp_path):
    seen = {}

    class Popen:
        def __init__(self, args, **kwargs):
            seen.update(kwargs["env"])

    monkeypatch.setattr(web_server.subprocess, "Popen", Popen)
    monkeypatch.setattr(web_server, "LOG_FILE", tmp_path / "web.log")
    real_start(tmp_path / "data", tmp_path / "web.url")
    assert seen["RECONIX_PYTHON"] == sys.executable


async def test_a_stale_link_is_not_opened(app, opened, web_launches):
    with socket.socket() as free:                          # a port nothing listens on
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
    persist.WEB_URL_FILE.write_text(LINK.replace(":3100/", f":{port}/"))
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        await settle(pilot)
        assert opened == [] and len(web_launches) == 1


def test_is_listening_needs_something_on_the_port():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        assert web_server.is_listening(f"http://127.0.0.1:{port}/login#token=x")
    assert not web_server.is_listening(f"http://127.0.0.1:{port}/login")
    assert not web_server.is_listening(None)


def test_it_cant_start_without_the_web_folder(monkeypatch, tmp_path):
    monkeypatch.setattr(web_server, "WEB_DIR", tmp_path)
    assert "web/" in real_problem()


# --- a stale install (a pull moved package-lock.json on) ------------------------------------
def _web_dir(tmp_path, locked, installed, record=None):
    """package.json + package-lock.json naming `locked` versions, node_modules holding
    `installed` ones, and npm's own record (node_modules/.package-lock.json) if given."""
    (tmp_path / "package.json").write_text(json.dumps(
        {"dependencies": {"next": "16.4.1"}, "devDependencies": {"vitest": "^4"}}))
    packages = {f"node_modules/{n}": {"version": v} for n, v in locked.items()}
    (tmp_path / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {"": {"name": "web"}, **packages}}))
    for name, version in installed.items():
        (tmp_path / "node_modules" / name).mkdir(parents=True)
        (tmp_path / "node_modules" / name / "package.json").write_text(
            json.dumps({"version": version}))
    if record is not None:
        (tmp_path / "node_modules" / ".package-lock.json").write_text(json.dumps(
            {"packages": {f"node_modules/{n}": {"version": v} for n, v in record.items()}}))
    return tmp_path


def test_an_older_installed_package_triggers_an_install(monkeypatch, tmp_path):
    web = _web_dir(tmp_path, {"next": "16.4.1"}, {"next": "16.3.8"})   # no npm record
    monkeypatch.setattr(web_server, "WEB_DIR", web)
    assert real_needs_install()


def test_a_moved_package_deep_down_triggers_an_install(monkeypatch, tmp_path):
    locked = {"next": "16.4.1", "@next/env": "16.4.1"}
    web = _web_dir(tmp_path, locked, {"next": "16.4.1"},
                   record={"next": "16.4.1", "@next/env": "16.3.8"})
    monkeypatch.setattr(web_server, "WEB_DIR", web)
    assert real_needs_install()


def test_an_up_to_date_install_is_left_alone(monkeypatch, tmp_path):
    # another platform's optional build is locked but never installed: that's fine
    locked = {"next": "16.4.1", "vitest": "4.1.12", "@next/swc-darwin-arm64": "16.4.1"}
    web = _web_dir(tmp_path, locked, {"next": "16.4.1", "vitest": "4.1.12"},
                   record={"next": "16.4.1", "vitest": "4.1.12"})
    monkeypatch.setattr(web_server, "WEB_DIR", web)
    assert not real_needs_install()
    (web / "package-lock.json").write_text("not json")        # unreadable: nothing to compare
    assert not real_needs_install()


def test_an_outdated_dev_package_counts_too(monkeypatch, tmp_path):
    web = _web_dir(tmp_path, {"next": "16.4.1", "vitest": "4.1.12"},
                   {"next": "16.4.1", "vitest": "3.2.7"})
    monkeypatch.setattr(web_server, "WEB_DIR", web)
    assert real_needs_install()


# --- the sign-in token never reaches a command line or the screen ---------------------------
def _recording_opener(monkeypatch):
    seen = []

    class Popen:
        def __init__(self, args, **kwargs):
            seen.append(list(args))

    monkeypatch.setattr(browser.sys, "platform", "linux")
    monkeypatch.setattr(browser.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(browser.subprocess, "Popen", Popen)
    return seen


def test_a_tokened_link_opens_through_a_private_redirect_file(monkeypatch):
    seen = _recording_opener(monkeypatch)
    assert real_open_url(LINK.strip())
    [[opener, target]] = seen
    assert opener == "xdg-open" and "token" not in target and target.startswith("file://")
    page = Path(target[len("file://"):])
    assert (page.stat().st_mode & 0o777) == 0o600
    assert (page.parent.stat().st_mode & 0o777) == 0o700
    assert 'content="0;url=http://127.0.0.1:3100/login#token=abc"' in page.read_text()
    browser.remove_redirect(str(page.parent))
    assert not page.parent.exists()


def test_the_redirect_file_is_removed_after_a_while(monkeypatch):
    seen = _recording_opener(monkeypatch)
    monkeypatch.setattr(browser, "REDIRECT_LIFETIME", 0.05)
    assert real_open_url(LINK.strip())
    folder = Path(seen[0][1][len("file://"):]).parent
    for _ in range(100):
        if not folder.exists():
            break
        time.sleep(0.02)
    assert not folder.exists()


def test_the_fallback_browser_gets_the_file_too(monkeypatch):
    opened = []
    monkeypatch.setattr(browser.shutil, "which", lambda name: None)
    monkeypatch.setattr(browser.webbrowser, "open", lambda url: opened.append(url) or True)
    assert real_open_url(LINK.strip())
    assert "token" not in opened[0]
    browser.remove_redirect(os.path.dirname(opened[0][len("file://"):]))
    monkeypatch.setattr(browser.webbrowser, "open", lambda url: False)
    before = set(browser._redirects)
    assert not real_open_url(LINK.strip())                    # nothing opened: nothing left
    assert browser._redirects == before


def test_a_plain_file_or_page_opens_as_it_is(monkeypatch):
    seen = _recording_opener(monkeypatch)
    assert real_open_url("file:///tmp/report.html")
    assert real_open_url("http://127.0.0.1:3100/")
    assert [target for _, target in seen] == ["file:///tmp/report.html",
                                              "http://127.0.0.1:3100/"]


async def test_without_a_browser_it_names_the_link_file_not_the_link(app, monkeypatch):
    monkeypatch.setattr(web_server, "is_listening", lambda url: True)
    monkeypatch.setattr(browser, "open_url", lambda url: False)
    persist.WEB_URL_FILE.write_text(LINK)
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        await settle(pilot)
        notes = _notes(app)
        assert str(persist.WEB_URL_FILE) in notes and "Couldn't open a browser" in notes
        assert "token" not in notes and "abc" not in notes
