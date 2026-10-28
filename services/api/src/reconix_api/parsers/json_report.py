"""A tool's JSON or JSON-lines output -> its result objects. Only reads; no database, no HTTP.

One reader for every tool that writes JSON. Where the results are in the document is
given by a path, e.g. "results[]" or "Results[].Vulnerabilities[]".
"""

import json
from typing import Any


class JsonParseError(ValueError):
    """The output is empty, cut off or not JSON."""


def parse(raw: str, items: str = "", lines: bool = False) -> list[dict[str, Any]]:
    """`items` is the path to the results; "" means the document itself is the list."""
    if not raw or not raw.strip():
        raise JsonParseError("EMPTY_OUTPUT")
    if lines:
        documents = _lines(raw)
    else:
        try:
            documents = pick(json.loads(raw), items)
        except json.JSONDecodeError as error:
            raise JsonParseError(f"NOT_JSON: {error}") from error
    return [document for document in documents if isinstance(document, dict)]


def _lines(raw: str) -> list[Any]:
    """One JSON object per line. Only the last line may be cut off; it is dropped."""
    rows = [line for line in raw.splitlines() if line.strip()]
    documents = []
    for number, line in enumerate(rows, start=1):
        try:
            documents.append(json.loads(line))
        except json.JSONDecodeError as error:
            if number < len(rows):
                raise JsonParseError(f"NOT_JSON_LINES: line {number}") from error
    return documents


def pick(value: Any, path: str) -> list[Any]:
    """Follow a path like "Results[].Vulnerabilities[]"; "[]" opens a list."""
    found = [value]
    for step in (part for part in path.split(".") if part):
        name = step.removesuffix("[]")
        found = [item.get(name) if name else item for item in found if isinstance(item, dict)]
        if step.endswith("[]"):
            found = [entry for item in found if isinstance(item, list) for entry in item]
    if not path:
        found = [entry for item in found if isinstance(item, list) for entry in item]
    return found


def get(item: dict[str, Any], path: str) -> Any:
    """A field by dotted path, e.g. "info.severity". Missing: None."""
    value: Any = item
    for name in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(name)
    return value
