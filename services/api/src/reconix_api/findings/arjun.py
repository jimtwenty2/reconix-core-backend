"""arjun text output -> a hidden-parameters finding.

arjun discovers undocumented HTTP parameters an endpoint still honours. Its stdout ends with
a summary line and one line per parameter with how it was found:

    [*] Scanning 0/1: http://host:3000/rest/products/search
    [✓] parameter detected: q, based on: http headers
    [+] Parameters found: q, security

The parameters themselves are a fact, not a weakness, so the finding is NONE severity. It is a
lead: these undocumented inputs are where the agent then tests injection, IDOR and the like. A
run that finds nothing makes no finding.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import host_of, lines, title
from reconix_api.models.enums import SeverityStatus

SCANNING = re.compile(r"Scanning\s+\d+/\d+:\s*(\S+)")
FOUND = re.compile(r"Parameters?\s+found:\s*(.+)$", re.IGNORECASE)
DETECTED = re.compile(r"parameter detected:\s*([^,]+?)\s*,\s*based on:\s*(.+)$", re.IGNORECASE)
MARKERS = ("parameter detected", "parameters found", "logicforcing", "probing the target")


def read(output: str) -> tuple[list[NewFinding], int]:
    rows = lines(output)
    if not any(any(marker in row.lower() for marker in MARKERS) for row in rows):
        raise OutputUnreadable("not arjun output")

    url = next((m.group(1) for row in rows if (m := SCANNING.search(row))), None)
    params: list[str] = []
    for row in rows:
        match = FOUND.search(row)
        if match:
            params = [p.strip() for p in match.group(1).split(",") if p.strip()]
            break
    # No summary line (older arjun, or a different locale): fall back to the per-param lines.
    bases: dict[str, str] = {}
    for row in rows:
        match = DETECTED.search(row)
        if match:
            name = match.group(1).strip()
            bases[name] = match.group(2).strip()
            if name not in params:
                params.append(name)

    if not url or not params:
        return [], 0

    detail = ", ".join(f"{p} ({bases[p]})" if p in bases else p for p in params)
    return [
        NewFinding(
            title=title(f"Hidden parameters at {host_of(url)}"),
            target=url,
            description=(
                f"arjun found {len(params)} undocumented parameter(s) the endpoint still "
                f"accepts at {url}: {detail}. These inputs are not in the documented interface "
                "and are worth testing for injection, access-control and logic flaws."
            ),
            severity=SeverityStatus.NONE,
            dedupe_key=dedupe_key("hidden_params", url),
            evidence=[NewEvidence(kind="arjun_params", content=", ".join(params), location=url)],
        )
    ], 0
