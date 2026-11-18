"""What a knowledge add-on talks about: the security references and topics in its passages.

The Security knowledge page draws them as a graph (documents linked to what they mention),
so two documents about the same CWE or topic sit together. Only names and counts leave
here, never the passages: the text was masked when it was saved, and stays in Qdrant.

References are exact ids (CVE-2021-44228, CWE-89, A03:2021, API1:2023, T1190, a Kali
catalog tool); topics are found from plain words (SQL injection, XSS, ...).
"""

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from reconix_ai.harness.catalog import tool_names

MAX_REFERENCES = 60  # per add-on, most mentioned first

CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
CVE_LOWER = re.compile(r"\bcve-(\d{4})-(\d{4,7})\b")
CWE = re.compile(r"\bCWE[-\s]?(\d{1,4})\b", re.IGNORECASE)
CWE_LOWER = re.compile(r"\bcwe[-\s]?(\d{1,4})\b")
OWASP_COMBINED = re.compile(r"\b(A(?:0[1-9]|10)):(20(?:17|21))\b|\b(API(?:[1-9]|10)):(2019|2023)\b")
ATTACK = re.compile(r"\b(T1\d{3}(?:\.\d{3})?)\b")


def _slug(topic: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", topic.lower()).strip("-")


def _render_trie(node: dict[str, Any]) -> str:
    """Render a character trie dict into a compact non-capturing alternation."""
    has_end = "" in node
    parts = [re.escape(ch) + _render_trie(sub) for ch, sub in sorted(node.items()) if ch != ""]
    if not parts:
        return ""
    body = parts[0] if len(parts) == 1 else "(?:" + "|".join(parts) + ")"
    return f"(?:{body})?" if has_end else body


def _compile_trie_pair(
    words: list[str], left: str, right: str
) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Compile (case-sensitive lowercase, ignore-case) trie regexes for a word list."""
    root: dict[str, Any] = {}
    for word in words:
        node = root
        for ch in word.lower():
            node = node.setdefault(ch, {})
        node[""] = None
    body = f"{left}({_render_trie(root)}){right}"
    return re.compile(body), re.compile(body, re.IGNORECASE)


# A topic and the words that name it (any case, whole words).
TOPICS: dict[str, tuple[str, ...]] = {
    "SQL injection": ("sql injection", "sqli", "sqlmap"),
    "Cross-site scripting": ("cross-site scripting", "cross site scripting", "xss"),
    "Command injection": ("command injection", "os command", "remote code execution", "rce"),
    "Server-side request forgery": ("server-side request forgery", "ssrf"),
    "Cross-site request forgery": ("cross-site request forgery", "csrf", "xsrf"),
    "Path traversal": ("path traversal", "directory traversal", "../"),
    "Broken authentication": ("authentication", "brute force", "credential stuffing", "mfa"),
    "Broken access control": ("access control", "authorization", "idor", "privilege escalation"),
    "Sensitive data exposure": ("sensitive data", "data exposure", "information disclosure"),
    "Secrets in code": ("hardcoded", "hard-coded", "api key", "secret key", "credentials"),
    "Security misconfiguration": ("misconfiguration", "default credentials", "debug mode"),
    "Cryptography": ("encryption", "tls", "ssl", "weak cipher", "hashing", "certificate"),
    "Deserialization": ("deserialization", "insecure deserialization"),
    "XML external entities": ("xml external entit", "xxe"),
    "Vulnerable components": ("outdated", "vulnerable component", "dependency", "dependencies"),
    "Network scanning": ("port scan", "open port", "service detection", "nmap"),
    "Phishing": ("phishing", "social engineering"),
    "Malware": ("malware", "ransomware", "trojan", "backdoor"),
    "Incident response": ("incident response", "forensic", "containment"),
    "Logging and monitoring": ("logging", "monitoring", "siem", "audit log"),
}
TOPIC_SECONDARY_WORDS = frozenset({"credentials"})
_TOPIC_META = {w: (_slug(topic), topic) for topic, words in TOPICS.items() for w in words}
_TOPIC_PATTERNS = tuple(
    _compile_trie_pair(group, r"(?<![\w])", r"(?![\w])")
    for group in (
        [w for w in _TOPIC_META if w not in TOPIC_SECONDARY_WORDS],
        sorted(TOPIC_SECONDARY_WORDS),
    )
    if group
)


@dataclass(frozen=True)
class Reference:
    type: str  # CVE, CWE, OWASP, ATTACK, TOOL or TOPIC
    ref_id: str  # e.g. CVE-2021-44228, CWE-89, A03:2021, T1190, NMAP, sql-injection
    label: str
    count: int  # passages that mention it


@dataclass(frozen=True)
class Span:
    """Where one reference or topic is named in a passage (character offsets)."""

    type: str
    ref_id: str
    label: str
    start: int
    end: int


def _scan_passage(passage: str) -> Iterator[tuple[str, str, str, int, int]]:
    """Yield (type, ref_id, label, start, end) for every match in one passage."""
    use_lower = passage.isascii()
    ci_text = passage.lower() if use_lower else passage
    for m in (CVE_LOWER if use_lower else CVE).finditer(ci_text):
        ref = f"CVE-{m.group(1)}-{m.group(2)}"
        yield "CVE", ref, ref, m.start(), m.end()
    for m in (CWE_LOWER if use_lower else CWE).finditer(ci_text):
        ref = f"CWE-{int(m.group(1))}"
        yield "CWE", ref, ref, m.start(), m.end()
    for m in OWASP_COMBINED.finditer(passage):
        ref = f"{m.group(1)}:{m.group(2)}" if m.group(1) else f"{m.group(3)}:{m.group(4)}"
        yield "OWASP", ref, ref, m.start(), m.end()
    for m in ATTACK.finditer(passage):
        yield "ATTACK", m.group(1), m.group(1), m.start(), m.end()
    tool_lower, tool_icase, tool_lookup = _tool_matcher()
    tool_regex = tool_lower if use_lower else tool_icase
    if tool_regex is not None:
        for m in tool_regex.finditer(ci_text):
            key = m.group(0) if use_lower else m.group(0).lower()
            name = tool_lookup[key]
            yield "TOOL", name.upper(), name, m.start(), m.end()
    for lower_rx, icase_rx in _TOPIC_PATTERNS:
        pattern = lower_rx if use_lower else icase_rx
        for m in pattern.finditer(ci_text):
            key = m.group(0) if use_lower else m.group(0).lower()
            ref_id, label = _TOPIC_META[key]
            yield "TOPIC", ref_id, label, m.start(), m.end()


def spans(passage: str) -> list[Span]:
    """Every place a reference or topic is named in one passage, in reading order. The same
    rules as references(), so a highlighted word is always one that was counted."""
    found = [
        Span(kind, ref_id, label, start, end)
        for kind, ref_id, label, start, end in _scan_passage(passage)
    ]
    return sorted(found, key=lambda s: (s.start, -s.end))


def references(passages: list[str]) -> list[Reference]:
    """Every reference and topic in the passages, counted once per passage, most mentioned
    first (then by id), at most MAX_REFERENCES."""
    counts: Counter[tuple[str, str, str]] = Counter()
    for passage in passages:
        counts.update(
            {(kind, ref_id, label) for kind, ref_id, label, _, _ in _scan_passage(passage)}
        )
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    return [
        Reference(type=kind, ref_id=ref_id, label=label, count=count)
        for (kind, ref_id, label), count in ranked[:MAX_REFERENCES]
    ]


@lru_cache(maxsize=1)
def _tool_matcher() -> tuple[re.Pattern[str] | None, re.Pattern[str] | None, dict[str, str]]:
    """Combined whole-word trie regexes (lowered, ignore-case) for catalog tools plus lookup."""
    names = sorted(
        (name for name in tool_names() if "_" not in name and len(name) >= 4),
        key=len,
        reverse=True,
    )
    if not names:
        return None, None, {}
    lookup = {name.lower(): name for name in names}
    lower_rx, icase_rx = _compile_trie_pair(names, r"(?<![\w-])", r"(?![\w-])")
    return lower_rx, icase_rx, lookup
