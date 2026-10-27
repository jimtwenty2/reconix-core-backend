"""One knowledge item: a CVE, a CWE, an OWASP risk, an ATT&CK technique or a tool guide.

Every source is turned into this one shape and saved as JSON Lines, one file
per source, so the loader reads them all the same way.
"""

import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path


class Source(StrEnum):
    CVE = "CVE"
    CWE = "CWE"
    OWASP_TOP10 = "OWASP_TOP10"
    OWASP_API_TOP10 = "OWASP_API_TOP10"
    ATTACK = "ATTACK"
    TOOL_GUIDE = "TOOL_GUIDE"


class TextFormat(StrEnum):
    TEXT = "TEXT"  # kept as one piece (each CVE, CWE and technique)
    MARKDOWN = "MARKDOWN"  # cut at its headings (OWASP pages, tool guides)


@dataclass(frozen=True)
class KnowledgeItem:
    source: Source
    ref_id: str  # e.g. "CVE-2021-44228", "CWE-89", "A03:2021", "T1190", "nmap"
    title: str
    text: str
    url: str = ""
    text_format: TextFormat = TextFormat.TEXT


def write_items(path: Path, items: list[KnowledgeItem]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as file:
        for item in items:
            file.write(json.dumps(asdict(item), ensure_ascii=False) + "\n")


def read_items(path: Path) -> list[KnowledgeItem]:
    items = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            items.append(item_from_dict(json.loads(line)))
    return items


def item_from_dict(data: dict) -> KnowledgeItem:
    return KnowledgeItem(
        source=Source(data["source"]),
        ref_id=data["ref_id"],
        title=data["title"],
        text=data["text"],
        url=data.get("url", ""),
        text_format=TextFormat(data.get("text_format", TextFormat.TEXT)),
    )
