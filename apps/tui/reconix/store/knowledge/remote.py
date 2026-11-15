"""Which local add-ons also live in the Core API's knowledge search: `remote.json`.

`/add-on` keeps the file on this computer and uploads it to the API
(`core_api/knowledge.py`), which answers with an id of its own. That id is remembered here,
keyed by the local source id, so removing the file here removes it there too.

    remote.json  {"format":"reconix.knowledge.remote/v1","add_ons":{<32 hex id>: <uuid>}}

It is a file of its own and not a column of `index.json`, whose rows are the contract the
web reads. Written 0600 like the index and read the same careful way; a mapping that can't be
read counts as empty, which costs an add-on the app no longer has an id for — never a file
that can't be listed or removed locally.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional

from ..errors import StoreValidationError
from ..persist import _write_private
from . import files, paths

REMOTE_FORMAT = "reconix.knowledge.remote/v1"
NAME = "remote.json"
MAX_REMOTE_BYTES = 64 * 1024          # 50 uploads (the knowledge limit) is under 6 KiB
_PROBLEM = "The list of uploaded add-ons is corrupt."


def remote_path() -> Path:
    return paths.knowledge_dir() / NAME


def all_remotes() -> Dict[str, str]:
    """Local source id -> the API's add-on id, in upload order; {} when nothing was uploaded."""
    try:
        data = files.read_private(remote_path(), MAX_REMOTE_BYTES, _PROBLEM)
    except StoreValidationError:
        return {}
    if data is None:
        return {}
    try:
        body = json.loads(data.decode("utf-8"))
        rows = body["add_ons"] if body.get("format") == REMOTE_FORMAT else None
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {}
    return {str(k): str(v) for k, v in rows.items()} if isinstance(rows, dict) else {}


def set_remote(source_id: str, knowledge_add_on_id: str) -> None:
    """Record that this local source is in the API's knowledge search under that id."""
    rows = all_remotes()
    rows[source_id] = knowledge_add_on_id
    _write(rows)


def pop_remote(source_id: str) -> Optional[str]:
    """The API's id for this source, forgetting the row; None when it was never uploaded."""
    rows = all_remotes()
    add_on_id = rows.pop(source_id, None)
    if add_on_id is not None:
        _write(rows)
    return add_on_id


def clear_remotes() -> List[str]:
    """Forget every upload and return the API ids, so they can be removed there too."""
    add_on_ids = list(all_remotes().values())
    try:
        remote_path().unlink()
    except OSError:
        pass
    return add_on_ids


def _write(rows: Dict[str, str]) -> None:
    paths.ensure_dir()
    body = {"format": REMOTE_FORMAT, "add_ons": rows}
    _write_private(remote_path(), json.dumps(body, indent=2) + "\n")
