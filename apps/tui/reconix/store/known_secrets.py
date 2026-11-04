"""The secrets Reconix itself holds, so `redact()` can mask them by their value.

The shapes in `redact.py` miss a secret that looks like any other word: the test account's
password or the session cookie the operator gave at the target login (`vault.py`), or a model
API key saved with /provider ("sk-mock-0000-1234" is too short for the sk- shape). Whatever
text is masked (chat, history, activity, feedback, saved files, what a model is sent) is
masked for these values as well.

`values()` returns them longest first (a longer value is masked before a shorter one inside
it), only those of `MIN_LENGTH` characters or more (a shorter one would mask ordinary words).
The values are never logged, printed or stored here: the vault keeps them in memory, the model
keys stay Fernet-sealed in the model settings file and are opened only to be compared.
"""

import sqlite3
from pathlib import Path
from typing import List, Optional, Set, Tuple

from . import lists

MIN_LENGTH = 4

# The opened model keys and the file state they were read from: the settings file is read
# again only when it (or the key file) changed, so masking stays cheap.
_KEYS_CACHE: List[Tuple[Optional[tuple], Tuple[str, ...]]] = [(None, ())]


def _login_values() -> Set[str]:
    """The cookie or password every assessment of this session holds for its target login."""
    found: Set[str] = set()
    for assessment in lists.ASSESSMENTS:
        for entry in assessment.vault:
            value = entry.secret.reveal() if entry.secret else ""
            found.add(value)
            found.add(value.strip())
    return found


def _stamp(path: Path, counter: bool = False) -> Optional[tuple]:
    """What tells a file changed: its path, time and size and, for the settings file, the
    change counter SQLite bumps on every commit (bytes 24-27 of its header: two quick writes
    can share a time and a size)."""
    try:
        info = path.stat()
        head = b""
        if counter:
            with path.open("rb") as handle:
                handle.seek(24)
                head = handle.read(4)
    except OSError:
        return None
    return (str(path), info.st_mtime_ns, info.st_size, head)


def _read_keys(db_path: Path, key_file: Path) -> Tuple[str, ...]:
    """Every API key saved in the model settings, opened. Reads only: a missing settings or
    key file is never created, and a key that can't be opened is skipped (it can't be shown
    either: what is saved is the sealed form)."""
    from cryptography.fernet import Fernet, InvalidToken

    try:
        fernet = Fernet(key_file.read_bytes())
        conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
    except (OSError, ValueError, sqlite3.Error):
        return ()
    keys = []
    try:
        rows = conn.execute("SELECT api_key_enc FROM providers WHERE api_key_enc IS NOT NULL")
        for (token,) in rows.fetchall():
            try:
                keys.append(fernet.decrypt(token).decode("utf-8").strip())
            except (InvalidToken, TypeError, UnicodeDecodeError):
                continue
    except sqlite3.Error:
        return ()
    finally:
        conn.close()
    return tuple(keys)


def _provider_values() -> Tuple[str, ...]:
    """The saved model API keys (cached until the settings file or the key file changes)."""
    from ..llm import config

    db_stamp, key_stamp = _stamp(config.DB_PATH, counter=True), _stamp(config.KEY_FILE)
    if db_stamp is None or key_stamp is None:
        return ()
    stamp = (db_stamp, key_stamp)
    cached_stamp, cached = _KEYS_CACHE[0]
    if cached_stamp != stamp:
        cached = _read_keys(config.DB_PATH, config.KEY_FILE)
        _KEYS_CACHE[0] = (stamp, cached)
    return cached


def values() -> List[str]:
    """Every secret Reconix holds, `MIN_LENGTH` characters or more, longest first."""
    found = _login_values()
    found.update(_provider_values())
    return sorted((v for v in found if len(v) >= MIN_LENGTH), key=len, reverse=True)
