"""The knowledge CLI: add, list, original and remove, over `reconix.store.knowledge`.

    add --file <path> --name <display name> --source web|terminal
    list
    original <id>          the decrypted original's raw bytes on stdout
    remove <id>

Output is one JSON object on stdout (`original` writes raw bytes). Exit codes: 0 ok; 2 refused
(`{"ok":false,"error":"<message for the operator>"}`, from the store's `StoreValidationError`
or a bad argument); 1 internal (a fixed message). Errors of `original` go to stderr as JSON so
stdout holds only file bytes. Keys, paths and file contents are never printed or logged.

`add` also sends the saved file to the Core API (`core_api/knowledge`), best effort, so the
API's agent can search it in its own store (the web page and the terminal share this one
implementation); the answer says whether it got there (`agent_searchable`, `remote_problem`).
`remove` drops the API's copy too. The API never decides whether the local file is saved.
"""

import argparse
import json
import sys
from typing import List, Optional

from ..core_api import knowledge as api
from ..core_api.client import CoreApiError
from ..store import knowledge
from ..store.errors import StoreValidationError
from ..store.knowledge.files import Source, valid_id

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_REFUSED = 2
INTERNAL_MESSAGE = "Couldn't update the knowledge files."


class _Refused(Exception):
    """A bad argument: reported like a store refusal."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # noqa: D102 - argparse hook
        raise _Refused("Invalid arguments. Use add, list, original or remove.")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="python -m reconix.knowledge", add_help=False)
    commands = parser.add_subparsers(dest="command", parser_class=_Parser, required=True)
    add = commands.add_parser("add", add_help=False)
    add.add_argument("--file", required=True)
    add.add_argument("--name", required=True)
    add.add_argument("--source", required=True, choices=list(knowledge.ORIGINS))
    commands.add_parser("list", add_help=False)
    for name in ("original", "remove"):
        commands.add_parser(name, add_help=False).add_argument("id")
    return parser


def source_json(source: Source) -> dict:
    return {"id": source.id, "name": source.name, "kind": source.kind, "bytes": source.bytes,
            "chunks": source.chunks, "added_at": source.added_at, "source": source.source,
            "original": source.original}


def _print(body: dict, stream=None) -> None:
    out = stream or sys.stdout
    out.write(json.dumps(body, ensure_ascii=False, separators=(",", ":")) + "\n")
    out.flush()


def _check_id(source_id: str) -> str:
    if not valid_id(source_id):
        raise StoreValidationError("Unknown add-on.")
    return source_id


def _run(args: argparse.Namespace) -> int:
    if args.command == "add":
        source = knowledge.add_source(args.file, name=args.name, origin=args.source)
        problem = _upload(source)
        _print({"ok": True, "source": source_json(source),
                "agent_searchable": not problem, "remote_problem": problem})
    elif args.command == "list":
        _print({"ok": True, "sources": [source_json(s) for s in knowledge.list_sources()]})
    elif args.command == "original":
        data = knowledge.read_original(_check_id(args.id))
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        source_id = _check_id(args.id)
        knowledge.remove_source(source_id)
        _forget(knowledge.pop_remote(source_id))
        _print({"ok": True})
    return EXIT_OK


def _upload(source: Source) -> str:
    """Send the saved file to the Core API too, so its agent can search it (the API reads its
    own store, never this folder). Best effort: the file is already saved here. "" when it is
    there, else why not — the reason is the API's own message, masked by the API itself.
    shortcut: the web kills this CLI after 60 s, so a huge file may time out there although it
    stays local; upgrade when the API takes the upload async."""
    try:
        # The bytes the store just kept, not the path read a second time: the API gets exactly
        # the file that is on disk, and nothing new can slip in between the two reads.
        kept = knowledge.read_original(source.id)
        add_on_id = api.upload_add_on(kept, source.name)
    except CoreApiError as exc:
        return str(exc)
    except StoreValidationError:
        return "the saved copy of it could not be read"
    except Exception:  # noqa: BLE001 - a broken upload must never undo the local add
        return "the upload did not finish"
    try:
        knowledge.set_remote(source.id, add_on_id)
    except Exception:  # noqa: BLE001 - a lost id only costs the later remove its unlink
        pass
    return ""


def _forget(add_on_id: Optional[str]) -> None:
    """Delete the API's copy too (best effort: the local files are already gone, and an id the
    API no longer has is not left behind). The JSON answer stays `{"ok":true}`: it only means
    the local remove, which is what the web page acts on."""
    if not add_on_id:
        return
    try:
        api.delete_add_on(add_on_id)
    except Exception:  # noqa: BLE001 - nothing the caller can still do about it
        pass


def main(argv: Optional[List[str]] = None) -> int:
    err = None                                  # `original` keeps stdout for the file bytes
    try:
        args = _parser().parse_args(argv)
        err = sys.stderr if args.command == "original" else None
        return _run(args)
    except (StoreValidationError, _Refused) as exc:
        _print({"ok": False, "error": str(exc)}, err)
        return EXIT_REFUSED
    except Exception:  # noqa: BLE001 - nothing but the fixed message may escape
        _print({"ok": False, "error": INTERNAL_MESSAGE}, err)
        return EXIT_INTERNAL
