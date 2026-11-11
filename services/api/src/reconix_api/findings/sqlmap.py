"""sqlmap text output -> a confirmed SQL-injection finding per vulnerable parameter.

sqlmap only reaches us in the validation phase, to confirm a weakness a scan flagged. When
it confirms an injection it prints an "sqlmap identified the following injection point(s)"
block: one "Parameter: NAME (PLACE)" with the injection "Type:"s under it, then the
"back-end DBMS". A confirmed injection is HIGH (CWE-89, A03:2021). A run that finds nothing
("all tested parameters ... do not appear to be injectable") makes no finding.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import lines, title
from reconix_api.models.enums import SeverityStatus

PARAM = re.compile(r"^Parameter:\s*(.+?)\s*\(([^)]+)\)\s*$")
TYPE = re.compile(r"^Type:\s*(.+)$")
DBMS = re.compile(r"back-end DBMS:\s*(.+)$", re.IGNORECASE)
URL = re.compile(r"testing URL '([^']+)'|target URL\s+'([^']+)'", re.IGNORECASE)


def read(output: str) -> tuple[list[NewFinding], int]:
    rows = lines(output)
    if not any("sqlmap" in row.lower() for row in rows):
        raise OutputUnreadable("not sqlmap output")
    dbms = next((m.group(1).strip() for row in rows if (m := DBMS.search(row))), "")
    url = next((g for row in rows if (m := URL.search(row)) for g in m.groups() if g), "the URL")
    findings: list[NewFinding] = []
    param = place = ""
    types: list[str] = []

    def flush() -> None:
        if param:
            findings.append(_finding(param, place, types, dbms, url))

    for row in rows:
        hit = PARAM.match(row)
        if hit:
            flush()
            param, place, types = hit.group(1).strip(), hit.group(2).strip(), []
            continue
        if param:
            typ = TYPE.match(row)
            if typ:
                types.append(typ.group(1).strip())
    flush()
    return findings, 0


def _finding(param: str, place: str, types: list[str], dbms: str, url: str) -> NewFinding:
    kinds = ", ".join(types) or "SQL injection"
    dbms_text = f" ({dbms})" if dbms else ""
    return NewFinding(
        title=title(f"Confirmed SQL injection: parameter {param} ({place})"),
        target=url,
        description=(
            f"sqlmap confirmed {place} parameter '{param}' is injectable{dbms_text}: {kinds}."
        ),
        severity=SeverityStatus.HIGH,
        dedupe_key=dedupe_key("sqlmap", url, param.lower(), place.lower()),
        evidence=[
            NewEvidence(
                kind="sqlmap_injection",
                content=f"Parameter: {param} ({place}) — {kinds}",
                location=url,
            )
        ],
        cwe_ids=["CWE-89"],
        owasp_id=["A03:2021"],
        remediation="Use parameterized queries / prepared statements; never build SQL from input.",
    )
