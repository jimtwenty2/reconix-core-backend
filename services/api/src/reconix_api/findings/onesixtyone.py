"""onesixtyone text output -> readable-SNMP findings.

onesixtyone probes UDP 161 with community strings. A host that answers prints a line
like "192.0.2.5 [public] Hardware: x86 ...": that community string is readable without
authentication -> MEDIUM (an SNMP exposure, A05:2021 / CWE-200). A silent host prints only
its "Scanning N hosts" banner and makes no finding.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import lines, title
from reconix_api.models.enums import SeverityStatus

# "<ip> [community] <system description>"
HIT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\[([^\]]+)\]\s*(.*)$")
SCANNING = re.compile(r"^Scanning\s+\d+\s+host", re.IGNORECASE)


def read(output: str) -> tuple[list[NewFinding], int]:
    rows = lines(output)
    if not any(SCANNING.match(row) or HIT.match(row) for row in rows):
        raise OutputUnreadable("not onesixtyone output")
    findings = []
    for row in rows:
        hit = HIT.match(row)
        if not hit:
            continue
        ip, community, descr = hit.group(1), hit.group(2), hit.group(3).strip()
        sysinfo = f" System: {descr}" if descr else ""
        findings.append(
            NewFinding(
                title=title(f"SNMP readable with community '{community}'"),
                target=ip,
                description=(
                    f"onesixtyone: the host answered SNMP with the community string "
                    f"'{community}' (readable without authentication).{sysinfo}"
                ),
                severity=SeverityStatus.MEDIUM,
                dedupe_key=dedupe_key("onesixtyone", ip, community.lower()),
                evidence=[NewEvidence(kind="snmp_community", content=row.strip(), location=ip)],
                cwe_ids=["CWE-200"],
                owasp_id=["A05:2021"],
                remediation=(
                    "Disable SNMP if unused, or replace default community strings and "
                    "restrict UDP 161 to trusted hosts."
                ),
            )
        )
    return findings, 0
