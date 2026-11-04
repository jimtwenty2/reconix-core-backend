"""An uploaded knowledge add-on: the file's bytes -> its text.

The same rules as the TUI's /add-on (apps/tui/reconix/store/knowledge/extract.py):
.txt .md .json .yaml .yml .docx .pdf, at most 10 MB. A .docx must unzip to at most 50 MB in
at most 2,000 parts, a PDF is read up to 2,000 pages, and YAML anchors, aliases, merge keys
and deep nesting are refused. The file is only read, never run, and every refusal is an
ApiError the person can act on.

JSON and YAML are masked here by key name (the harness's mask_value), before they are
written back as text: as plain text, a secret under "Authorization" or one with an escaped
quote would get past the text rules. They are written back on one line, never indented,
so a deeply nested file cannot grow past its own size. The caller masks the whole text
again and only then cuts it at MAX_TEXT_CHARS (cut_text), so a cut never splits a secret.
"""

import io
import json
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import yaml
from docx import Document
from pypdf import PdfReader

from reconix_ai.harness import mask_value
from reconix_api.core.errors import ApiError

KINDS = {
    ".txt": "TXT",
    ".md": "MD",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".docx": "DOCX",
    ".pdf": "PDF",
}
SUPPORTED = ".txt .md .json .yaml .yml .docx .pdf"
LABELS = {
    "TXT": "text",
    "MD": "Markdown",
    "JSON": "JSON",
    "YAML": "YAML",
    "DOCX": "Word",
    "PDF": "PDF",
}
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TEXT_CHARS = 2 * 1024 * 1024
MAX_NAME = 120
MAX_PDF_PAGES = 2000
MAX_DOCX_UNZIPPED = 50 * 1024 * 1024
MAX_DOCX_PARTS = 2000
MAX_YAML_DEPTH = 100
YAML_MERGE_TAG = "tag:yaml.org,2002:merge"

TEXT_LIMIT = "TEXT_LIMIT"  # the text was cut at MAX_TEXT_CHARS
PAGE_LIMIT = "PAGE_LIMIT"  # the PDF was read up to MAX_PDF_PAGES


@dataclass(frozen=True)
class FileText:
    text: str
    cut: str | None  # TEXT_LIMIT or PAGE_LIMIT when a limit cut the text short


class YamlRefused(yaml.YAMLError):
    """The YAML uses something that can expand without end; the message says what."""


class NoExpandingLoader(yaml.SafeLoader):
    """yaml.SafeLoader that refuses anchors, aliases, merge keys and deep nesting, which let
    a few kilobytes grow to gigabytes ("billion laughs") or exhaust the stack."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self.depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise YamlRefused("YAML aliases (*name) aren't supported.")
        if getattr(self.peek_event(), "anchor", None) is not None:
            raise YamlRefused("YAML anchors (&name) aren't supported.")
        self.depth += 1
        try:
            if self.depth > MAX_YAML_DEPTH:
                raise YamlRefused(f"That YAML is nested more than {MAX_YAML_DEPTH} levels deep.")
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        if any(key.tag == YAML_MERGE_TAG for key, _ in node.value):
            raise YamlRefused("YAML merge keys (<<) aren't supported.")
        super().flatten_mapping(node)


def kind_of(file_name: str) -> str:
    """TXT, MD, JSON, YAML, DOCX or PDF, from the name's extension."""
    suffix = PurePosixPath(base_name(file_name)).suffix.lower()
    if suffix == ".doc":
        raise ApiError(
            422,
            "UNSUPPORTED_FILE_TYPE",
            "Save it as .docx first (old .doc files aren't supported).",
        )
    if suffix not in KINDS:
        raise ApiError(422, "UNSUPPORTED_FILE_TYPE", f"Use one of these file types: {SUPPORTED}.")
    return KINDS[suffix]


def display_name(masked_name: str) -> str:
    """The name to save and show: no folders, on one line, at most MAX_NAME characters.
    Mask the whole name before this, so a secret is never cut in half and missed."""
    # Control characters out too: "\x1b[..." would drive the terminal that shows the name.
    shown = "".join(ch for ch in base_name(masked_name) if ch.isprintable() or ch.isspace())
    flat = " ".join(shown.split())
    return flat[:MAX_NAME].rstrip() or "untitled"


def base_name(file_name: str) -> str:
    return file_name.replace("\\", "/").rsplit("/", 1)[-1]


def read_text(kind: str, data: bytes) -> FileText:
    """The file's text, not cut yet (see cut_text). Any parser failure is a clear refusal."""
    if len(data) > MAX_FILE_BYTES:
        raise ApiError(413, "FILE_TOO_LARGE", "That file is over 10 MB.")
    label = LABELS[kind]
    try:
        text, cut = READERS[kind](data)
    except RecursionError:
        raise unreadable(f"That {label} file is nested too deeply to read.") from None
    except MemoryError:
        raise unreadable(f"That {label} file is too large to read.") from None
    except (OSError, ValueError):
        raise unreadable(f"Couldn't read that {label} file.") from None
    return FileText(text, cut)


def cut_text(masked_text: str, cut: str | None) -> tuple[str, str | None]:
    """At most MAX_TEXT_CHARS, cut at the last space before it when there is one. Mask
    the whole text before this."""
    if len(masked_text) <= MAX_TEXT_CHARS:
        return masked_text, cut
    end = masked_text.rfind(" ", MAX_TEXT_CHARS // 2, MAX_TEXT_CHARS)
    return masked_text[: end if end != -1 else MAX_TEXT_CHARS], TEXT_LIMIT


def unreadable(message: str) -> ApiError:
    return ApiError(422, "FILE_UNREADABLE", message)


def from_text(data: bytes) -> tuple[str, str | None]:
    return data.decode("utf-8", errors="replace"), None


def from_json(data: bytes) -> tuple[str, str | None]:
    try:
        value = json.loads(data.decode("utf-8", errors="replace"))
    except ValueError:
        raise unreadable("That file isn't valid JSON.") from None
    return masked_json_text(value), None


def from_yaml(data: bytes) -> tuple[str, str | None]:
    loader = NoExpandingLoader(data.decode("utf-8", errors="replace"))
    try:
        value = loader.get_single_data()
    except YamlRefused as refused:
        raise unreadable(f"That YAML file can't be added: {refused}") from None
    except yaml.YAMLError:
        raise unreadable("That file isn't valid YAML.") from None
    finally:
        loader.dispose()
    if value is None:
        return "", None
    return masked_json_text(value), None


def masked_json_text(value: Any) -> str:
    """value with every secret masked by key name, as one line of JSON. Dates and the
    like become text on the way (mask_value)."""
    masked, _ = mask_value(value)
    return json.dumps(masked, ensure_ascii=False, default=str)


def from_docx(data: bytes) -> tuple[str, str | None]:
    check_docx_size(data)
    try:
        document = Document(io.BytesIO(data))
        parts = [paragraph.text for paragraph in document.paragraphs if paragraph.text.strip()]
        for table in document.tables:
            for row in table.rows:
                line = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                if line:
                    parts.append(line)
    except (RecursionError, MemoryError):
        raise
    except Exception:  # noqa: BLE001 - a crafted file can raise anything; refuse it
        raise unreadable("Couldn't read that Word file.") from None
    return "\n\n".join(parts), None


def check_docx_size(data: bytes) -> None:
    """Refuse a zip bomb, from the zip's own list of parts, before anything is unpacked."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            parts = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile):
        raise unreadable("Couldn't read that Word file.") from None
    if len(parts) > MAX_DOCX_PARTS:
        raise unreadable("That Word file has too many parts to read.")
    if sum(part.file_size for part in parts) > MAX_DOCX_UNZIPPED:
        raise unreadable("That Word file unpacks to over 50 MB; add a smaller copy.")


def from_pdf(data: bytes) -> tuple[str, str | None]:
    try:
        reader = PdfReader(io.BytesIO(data))
        locked = reader.is_encrypted and not reader.decrypt("")  # a blank password may open it
    except Exception:  # noqa: BLE001 - a crafted file can raise anything; refuse it
        raise unreadable("Couldn't read that PDF.") from None
    if locked:
        raise unreadable("That PDF is encrypted; add an unencrypted copy.")
    parts, total = [], 0
    try:
        for number, page in enumerate(reader.pages):
            if number >= MAX_PDF_PAGES:
                return "\n\n".join(parts), PAGE_LIMIT
            if total >= MAX_TEXT_CHARS:
                return "\n\n".join(parts), TEXT_LIMIT
            text = page.extract_text() or ""
            if text.strip():
                parts.append(text)
                total += len(text) + 2
    except (RecursionError, MemoryError):
        raise
    except Exception:  # noqa: BLE001 - a crafted file can raise anything; refuse it
        raise unreadable("Couldn't read that PDF.") from None
    return "\n\n".join(parts), None


READERS: dict[str, Callable[[bytes], tuple[str, str | None]]] = {
    "TXT": from_text,
    "MD": from_text,
    "JSON": from_json,
    "YAML": from_yaml,
    "DOCX": from_docx,
    "PDF": from_pdf,
}
