"""What a knowledge add-on talks about: the security references and topics in its passages.

The Security knowledge page draws them as a graph (documents linked to what they mention),
so two documents about the same CWE or topic sit together. Only names and counts leave
here, never the passages: the text was masked when it was saved, and stays in Qdrant.

References are exact ids (CVE-2021-44228, CWE-89, A03:2021, API1:2023, T1190, a Kali
catalog tool); topics are found from plain words (SQL injection, XSS, ...).
"""

import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache

from reconix_ai.harness.catalog import tool_names

MAX_REFERENCES = 60  # per add-on, most mentioned first

CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
CWE = re.compile(r"\bCWE[-\s]?(\d{1,4})\b", re.IGNORECASE)
OWASP = re.compile(r"\b(A(?:0[1-9]|10)):(20(?:17|21))\b")
OWASP_API = re.compile(r"\b(API(?:[1-9]|10)):(2019|2023)\b")
ATTACK = re.compile(r"\b(T1\d{3}(?:\.\d{3})?)\b")

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
TOPIC_WORDS = {
    topic: re.compile(
        r"(?<![\w])(?:" + "|".join(re.escape(w) for w in words) + r")(?![\w])", re.IGNORECASE
    )
    for topic, words in TOPICS.items()
}


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


def spans(passage: str) -> list[Span]:
    """Every place a reference or topic is named in one passage, in reading order. The same
    rules as references(), so a highlighted word is always one that was counted."""
    found: list[Span] = []
    for m in CVE.finditer(passage):
        ref = f"CVE-{m.group(1)}-{m.group(2)}"
        found.append(Span("CVE", ref, ref, m.start(), m.end()))
    for m in CWE.finditer(passage):
        ref = f"CWE-{int(m.group(1))}"
        found.append(Span("CWE", ref, ref, m.start(), m.end()))
    for m in [*OWASP.finditer(passage), *OWASP_API.finditer(passage)]:
        ref = f"{m.group(1)}:{m.group(2)}"
        found.append(Span("OWASP", ref, ref, m.start(), m.end()))
    for m in ATTACK.finditer(passage):
        found.append(Span("ATTACK", m.group(1), m.group(1), m.start(), m.end()))
    for name, word in _tool_patterns():
        for m in word.finditer(passage):
            found.append(Span("TOOL", name.upper(), name, m.start(), m.end()))
    for topic, word in TOPIC_WORDS.items():
        for m in word.finditer(passage):
            found.append(Span("TOPIC", _slug(topic), topic, m.start(), m.end()))
    return sorted(found, key=lambda s: (s.start, -s.end))


def references(passages: list[str]) -> list[Reference]:
    """Every reference and topic in the passages, counted once per passage, most mentioned
    first (then by id), at most MAX_REFERENCES."""
    counts: Counter[tuple[str, str, str]] = Counter()
    for passage in passages:
        counts.update({(s.type, s.ref_id, s.label) for s in spans(passage)})
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    return [
        Reference(type=kind, ref_id=ref_id, label=label, count=count)
        for (kind, ref_id, label), count in ranked[:MAX_REFERENCES]
    ]


@lru_cache(maxsize=1)
def _tool_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """The catalog's tools a document names: whole words, never the internal helpers."""
    names = sorted(name for name in tool_names() if "_" not in name and len(name) >= 4)
    return [
        (name, re.compile(rf"(?<![\w-]){re.escape(name)}(?![\w-])", re.IGNORECASE))
        for name in names
    ]


def _slug(topic: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", topic.lower()).strip("-")
