"""schemathesis (v4) text output -> API testing findings, one per (operation, check).

schemathesis fuzzes every operation in the OpenAPI schema and prints a FAILURES section:
each operation ("METHOD /path") lists the checks it failed, by code ("ST101 Server error").
A server error (ST101, a 5xx the API did not handle) is a real weakness -> MEDIUM, and the
response body it prints often leaks a stack trace or SQL, kept as evidence. The other codes
(undocumented status/content-type, schema or method mismatches) are contract problems ->
LOW. The run's summary counts are not findings.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import lines, title
from reconix_api.models.enums import SeverityStatus

# An operation header is a line of underscores around " METHOD /path ".
OPERATION = re.compile(r"^_+\s*([A-Z]+ /\S*)\s*_+$")
CHECK = re.compile(r"^-\s*(ST\d+)\s+(.*)$")
STATUS = re.compile(r"^\[(\d{3})\]")
SERVER_ERROR = "ST101"
# The failures section starts here; the per-phase summary ("Test Phases:") ends it.
START = re.compile(r"^=+\s*FAILURES\s*=+$")
END = re.compile(r"^(Test Phases:|=+\s*\d+ failures)", re.IGNORECASE)


def read(output: str) -> tuple[list[NewFinding], int]:
    rows = lines(output)
    if not any("Schemathesis" in row or "schemathesis" in row for row in rows):
        raise OutputUnreadable("not schemathesis output")
    base = _base_url(rows)
    findings: list[NewFinding] = []
    seen: set[tuple[str, str]] = set()
    operation = ""
    status = ""
    in_failures = False
    for row in rows:
        if START.match(row):
            in_failures = True
            continue
        if not in_failures:
            continue
        if END.match(row):
            break
        op = OPERATION.match(row)
        if op:
            operation, status = op.group(1), ""
            continue
        stat = STATUS.match(row)
        if stat:
            status = stat.group(1)
        check = CHECK.match(row)
        if check and operation:
            code, name = check.group(1), check.group(2).strip()
            if (operation, code) in seen:
                continue
            seen.add((operation, code))
            findings.append(_finding(base, operation, code, name, status))
    return findings, 0


def _base_url(rows: list[str]) -> str:
    for row in rows:
        hit = re.search(r"Base URL:\s*(\S+)", row)
        if hit:
            return hit.group(1)
    for row in rows:
        hit = re.search(r"Loaded specification from\s+(\S+)", row)
        if hit:
            return hit.group(1)
    return "the API"


def _finding(base: str, operation: str, code: str, name: str, status: str) -> NewFinding:
    server_error = code == SERVER_ERROR
    severity = SeverityStatus.MEDIUM if server_error else SeverityStatus.LOW
    detail = f"{code} {name}" + (f" (HTTP {status})" if status else "")
    description = f"schemathesis found {name} ({code}) on {operation}" + (
        f"; the API returned HTTP {status} without handling it."
        if server_error
        else ". The response did not match the documented contract."
    )
    return NewFinding(
        title=title(f"API {operation}: {name}"),
        target=f"{base.rstrip('/')} {operation}".strip(),
        description=description,
        severity=severity,
        dedupe_key=dedupe_key("schemathesis", operation, code),
        evidence=[NewEvidence(kind="schemathesis_check", content=detail, location=operation)],
        cwe_ids=["CWE-391"] if server_error else [],
        owasp_id=["API8:2023"] if not server_error else ["API7:2023"],
    )
