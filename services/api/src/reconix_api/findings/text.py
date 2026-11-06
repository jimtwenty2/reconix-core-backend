"""Small helpers for the readers of tools that print plain text, not JSON or XML."""

import re
from urllib.parse import urlsplit

# Terminal escapes (ffuf redraws its line with "ESC[2K") and carriage returns.
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
MAX_TITLE = 150


def lines(output: str) -> list[str]:
    """The output's lines without terminal escapes, empty lines dropped."""
    text = ANSI.sub("", output or "").replace("\r", "\n")
    return [line.rstrip() for line in text.split("\n") if line.strip()]


def split_top(text: str, separator: str = ",") -> list[str]:
    """Split on `separator` outside [brackets]: "A[x,y], B" -> ["A[x,y]", "B"]."""
    parts, depth, current = [], 0, []
    for char in text:
        depth += {"[": 1, "]": -1}.get(char, 0)
        if char == separator and depth <= 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def cves(text: str) -> list[str]:
    """The CVE ids in a text, upper case, each once, in order."""
    return list(dict.fromkeys(match.upper() for match in CVE.findall(text or "")))


def host_of(url: str) -> str:
    """The host (and port) of a URL, or the text itself when it is not a URL."""
    try:
        return urlsplit(url).netloc or url
    except ValueError:
        return url


def base_url(url: str) -> str:
    """A URL without its trailing slash, so "http://h/" and "http://h" are one site."""
    return url.rstrip("/") or url


def title(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_TITLE else text[: MAX_TITLE - 1] + "…"
