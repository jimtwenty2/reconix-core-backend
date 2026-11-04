"""Open a URL or a saved file in the operator's browser without disturbing the TUI.

The desktop opener is launched detached with its output silenced (a browser that logs to
the terminal would scribble over the TUI); `webbrowser` is the fallback.

A link that carries a secret in its #fragment or ?query (the web dashboard's sign-in token)
is never put on the opener's command line, where every user's process list shows it: the
browser opens a private redirect file instead (folder 0700, file 0600, removed after a
minute), as the dashboard's own launcher does (web/scripts/serve-helpers.mjs).
"""

import atexit
import html
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import webbrowser
from pathlib import Path
from typing import Optional, Set
from urllib.parse import urlsplit

REDIRECT_LIFETIME = 60.0     # seconds: enough for the browser to read the redirect file

_redirects: Set[str] = set()  # redirect folders not removed yet (removed at exit too)
_lock = threading.Lock()


def open_url(url: str) -> bool:
    """True if a browser (or the desktop's opener) was launched for `url`."""
    if not carries_secret(url):
        return _launch(url)
    folder = redirect_folder(url)
    if folder is None:
        return False
    if not _launch((Path(folder) / "open.html").as_uri()):
        remove_redirect(folder)
        return False
    timer = threading.Timer(REDIRECT_LIFETIME, remove_redirect, args=(folder,))
    timer.daemon = True
    timer.start()
    return True


def open_path(display_path: str) -> bool:
    """Open a saved file (a report) with the desktop's default app."""
    try:
        url = Path(display_path).resolve().as_uri()
    except (OSError, ValueError):
        return False
    return open_url(url)


def carries_secret(url: str) -> bool:
    """A web link with a #fragment or ?query (a token may be in either)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    return parts.scheme in {"http", "https"} and bool(parts.fragment or parts.query)


def redirect_folder(url: str) -> Optional[str]:
    """A new private folder holding open.html, which sends the browser on to `url`."""
    try:
        folder = tempfile.mkdtemp(prefix="reconix-web-")          # 0700
    except OSError:
        return None
    with _lock:
        _redirects.add(folder)
    href = html.escape(url, quote=True)
    page = (f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" '
            f'content="0;url={href}"><title>Reconix</title>'
            f'<a href="{href}">Open the Reconix dashboard</a>\n')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.path.join(folder, "open.html"), flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(page)
    except OSError:
        remove_redirect(folder)
        return None
    return folder


def remove_redirect(folder: str) -> None:
    with _lock:
        _redirects.discard(folder)
    shutil.rmtree(folder, ignore_errors=True)


@atexit.register
def _remove_all() -> None:
    for folder in list(_redirects):
        remove_redirect(folder)


def _launch(target: str) -> bool:
    opener = {"linux": "xdg-open", "darwin": "open"}.get(sys.platform)
    if opener and shutil.which(opener):
        try:
            subprocess.Popen([opener, target], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            return True
        except OSError:
            pass
    try:
        return webbrowser.open(target)
    except (OSError, webbrowser.Error):
        return False
