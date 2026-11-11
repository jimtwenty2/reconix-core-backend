"""dalfox text output -> XSS findings.

dalfox prints one line per confirmed hit, tagged with what it is:
  [POC][V] ...   a verified cross-site scripting hit  -> HIGH (CWE-79)
  [POC][R] ...   a reflected parameter (not confirmed) -> MEDIUM
Only these tagged lines become findings. A scan that finds nothing ("XSS found 0") makes
no finding. The injected parameter marker in the URL is evidence, not a secret.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import host_of, lines, title
from reconix_api.models.enums import SeverityStatus

POC = re.compile(r"^\[POC\](\[[A-Z]\])+", re.IGNORECASE)
URL = re.compile(r"(https?://\S+)")


def read(output: str) -> tuple[list[NewFinding], int]:
    rows = lines(output)
    if not any("dalfox" in row.lower() or "XSS found" in row for row in rows):
        raise OutputUnreadable("not dalfox output")
    findings = [_finding(row) for row in rows if POC.match(row)]
    return [finding for finding in findings if finding is not None], 0


def _finding(row: str) -> NewFinding | None:
    tags = set(re.findall(r"\[([A-Z])\]", row.split("http", 1)[0]))
    match = URL.search(row)
    if not match:
        return None
    url = match.group(1)
    verified = "V" in tags
    return NewFinding(
        title=title(
            f"{'Verified' if verified else 'Reflected'} cross-site scripting at {host_of(url)}"
        ),
        target=url,
        description=(
            "dalfox "
            + ("confirmed a cross-site scripting hit" if verified else "saw a reflected parameter")
            + f" at {url}."
        ),
        severity=SeverityStatus.HIGH if verified else SeverityStatus.MEDIUM,
        dedupe_key=dedupe_key("dalfox_xss", url, "v" if verified else "r"),
        evidence=[NewEvidence(kind="dalfox_poc", content=row.strip(), location=url)],
        cwe_ids=["CWE-79"],
        owasp_id=["A03:2021"],
        remediation="Encode output for its context and validate input; apply a CSP.",
    )
