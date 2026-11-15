"""The Core API's knowledge add-ons: files the agent can search (`/knowledge-add-ons`).

`/add-on` keeps the file on this computer (`store/knowledge`) and sends it here too, so the
API's agent finds it in its own knowledge search. The upload is one multipart/form-data form
built by hand (stdlib only, apps/CLAUDE.md "Data") and carries the session token like every
other call. Nothing here reads or writes the app's store: the caller passes the bytes it
already saved, so the API gets exactly the file that is on disk.

Every failure is the API's own `CoreApiError` (or "not running"); the caller decides what to
say, because a file that only reached this computer is still a saved file.
"""

import mimetypes
import uuid
from typing import Dict, Tuple
from urllib.parse import quote

from . import connect

# sessions.interface: this app is the terminal.
INTERFACE = "cli"
_UNKNOWN_TYPE = "application/octet-stream"


def upload_add_on(data: bytes, name: str, interface: str = INTERFACE) -> str:
    """Add this file to the API's knowledge search; returns its knowledge_add_on_id.

    `name` is the file's own name (its extension picks the type) and its display name.
    """
    body, content_type = _form(name, data, {"interface": interface, "name": name})
    made = connect.request("POST", "/knowledge-add-ons", raw_body=body, content_type=content_type)
    return str(made["knowledge_add_on_id"])


def delete_add_on(knowledge_add_on_id: str) -> None:
    """Remove one add-on and its passages from the API's knowledge search."""
    connect.request("DELETE", f"/knowledge-add-ons/{quote(knowledge_add_on_id, safe='')}")


def _form(filename: str, data: bytes, fields: Dict[str, str]) -> Tuple[bytes, str]:
    """The multipart/form-data body of one file plus its text fields, and its Content-Type."""
    # A random boundary: it would only break the form if the file held this exact line.
    boundary = f"reconix{uuid.uuid4().hex}"
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'
        for key, value in fields.items()
    ]
    mime = mimetypes.guess_type(filename)[0] or _UNKNOWN_TYPE
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{_quoted(filename)}"\r\nContent-Type: {mime}\r\n\r\n'
    )
    body = "".join(parts).encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, f"multipart/form-data; boundary={boundary}"


def _quoted(text: str) -> str:
    """`text` inside a form header's quoted string: a name or backslash is escaped."""
    return text.replace("\\", "\\\\").replace('"', '\\"')
