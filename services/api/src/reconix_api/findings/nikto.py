"""nikto text output -> findings, one per "+" item line.

nikto does not rate what it reports, so severity is UNKNOWN by default: the item is worth
a look, but nikto does not say how bad it is. Two exceptions, raised only on nikto's own
words: a missing security header -> LOW (a header is either there or not); a line naming a
CVE -> UNKNOWN still, but the CVE is kept for the analyst. Header/banner facts and summary
lines ("N requests", target info) make no finding.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import cves, lines, title
from reconix_api.models.enums import SeverityStatus

ITEM = re.compile(r"^\+\s*(.*)$")
SKIP = re.compile(
    r"^(Target |Start Time|End Time|Server:|No CGI|SSL Info|\d+ host|\d+ requests|"
    r"\d+ error|Retrieved |Root page)",
    re.IGNORECASE,
)
# nikto writes an item id in brackets, e.g. "[013587] /: ...". Dropped from the title.
ID = re.compile(r"^\[\d+\]\s*")


def read(output: str) -> tuple[list[NewFinding], int]:
    rows = lines(output)
    if not any("Nikto" in row for row in rows):
        raise OutputUnreadable("not nikto output")
    target = _target(rows)
    findings: list[NewFinding] = []
    missing_headers: list[tuple[str, str]] = []
    for row in rows:
        match = ITEM.match(row)
        if not match or SKIP.match(match.group(1)):
            continue
        text = ID.sub("", match.group(1)).strip()
        if _is_missing_header(text):
            missing_headers.append((text, row))  # grouped below, not one finding each
        else:
            findings.append(_finding(match.group(1), target, row))
    if missing_headers:
        findings.append(_missing_headers_finding(missing_headers, target))
    return findings, 0


def _is_missing_header(text: str) -> bool:
    low = text.lower()
    return "security header missing" in low or "header: missing" in low


def _missing_headers_finding(items: list[tuple[str, str]], target: str) -> NewFinding:
    """One finding for all missing security headers, not one per header."""
    names = [text for text, _ in items]
    return NewFinding(
        title=title(f"{len(names)} security header(s) missing on {target}"),
        target=target,
        description="nikto reports these response headers are missing: " + "; ".join(names),
        severity=SeverityStatus.LOW,
        dedupe_key=dedupe_key("nikto_missing_headers", target),
        evidence=[
            NewEvidence(kind="nikto_item", content=row.strip(), location=target) for _, row in items
        ],
    )


def _target(rows: list[str]) -> str:
    host = port = ""
    for row in rows:
        hit = re.search(r"Target Hostname:\s*(\S+)", row)
        if hit:
            host = hit.group(1)
        hit = re.search(r"Target Port:\s*(\d+)", row)
        if hit:
            port = hit.group(1)
    if host and port:
        return f"{host}:{port}"
    return host or "the web server"


def _finding(item: str, target: str, row: str) -> NewFinding:
    text = ID.sub("", item).strip()
    severity = (
        SeverityStatus.LOW
        if "security header missing" in text.lower() or "header: missing" in text.lower()
        else SeverityStatus.UNKNOWN
    )
    return NewFinding(
        title=title(f"nikto: {text}"),
        target=target,
        description=f"nikto reported: {text}",
        severity=severity,
        dedupe_key=dedupe_key("nikto", target, text.lower()),
        evidence=[NewEvidence(kind="nikto_item", content=row.strip(), location=target)],
        cve_ids=cves(text),
    )
