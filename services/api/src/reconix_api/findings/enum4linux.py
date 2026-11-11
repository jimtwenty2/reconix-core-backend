"""enum4linux text output -> SMB enumeration findings.

enum4linux prints "[+]" lines for what it learned over SMB (139/445). Most are plain
facts (NONE). The one that matters for security is a null session: when the server
"allows sessions using username '', password ''", anyone on the network can enumerate it
without credentials -> MEDIUM (a misconfiguration, A05:2021 / CWE-287). Listed shares and
enumerated users are kept as LOW (exposed surface), capped so a big domain can't flood.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import lines, title
from reconix_api.models.enums import SeverityStatus

PLUS = re.compile(r"^\[\+\]\s*(.*)$")
NULL_SESSION = re.compile(r"allows sessions using username\s*'(.*)',\s*password\s*'(.*)'", re.I)
SHARE = re.compile(r"^\s*(\S+)\s+Disk|Mapping:\s*OK", re.I)
USER = re.compile(r"user:\[([^\]]+)\]|^\s*index:.*RID.*Username:\[([^\]]+)\]", re.I)
MAX_ROWS = 25


def read(output: str) -> tuple[list[NewFinding], int]:
    rows = lines(output)
    target = _target(rows)
    if not any("enum4linux" in row.lower() or "Target Information" in row for row in rows):
        raise OutputUnreadable("not enum4linux output")
    findings: list[NewFinding] = []
    shares: list[str] = []
    users: list[str] = []
    for row in rows:
        null = NULL_SESSION.search(row)
        if null and null.group(1) == "" and null.group(2) == "":
            findings.append(
                _finding(
                    "SMB null session allowed (anonymous access)",
                    target,
                    row,
                    SeverityStatus.MEDIUM,
                    "smb_null_session",
                    cwe=["CWE-287"],
                    owasp=["A05:2021"],
                    remediation="Disable anonymous/guest SMB sessions; require authentication.",
                )
            )
        share = SHARE.search(row)
        if share and share.group(1):
            shares.append(share.group(1))
        user = USER.search(row)
        if user:
            users.append(next(g for g in user.groups() if g))
    for name in dict.fromkeys(shares[:MAX_ROWS]):
        findings.append(
            _finding(f"SMB share exposed: {name}", target, name, SeverityStatus.LOW, "smb_share")
        )
    for name in dict.fromkeys(users[:MAX_ROWS]):
        findings.append(
            _finding(f"SMB user enumerated: {name}", target, name, SeverityStatus.LOW, "smb_user")
        )
    return findings, 0


def _target(rows: list[str]) -> str:
    for row in rows:
        hit = re.search(r"Target\s*\.*\s*(\S+)", row)
        if hit:
            return hit.group(1)
    return "the SMB host"


def _finding(
    label: str,
    target: str,
    evidence: str,
    severity: SeverityStatus,
    kind: str,
    cwe: list[str] | None = None,
    owasp: list[str] | None = None,
    remediation: str | None = None,
) -> NewFinding:
    return NewFinding(
        title=title(label),
        target=target,
        description=f"enum4linux (SMB): {label}",
        severity=severity,
        dedupe_key=dedupe_key("enum4linux", target, kind, label.lower()),
        evidence=[NewEvidence(kind=kind, content=evidence.strip(), location=target)],
        cwe_ids=cwe or [],
        owasp_id=owasp or [],
        remediation=remediation,
    )
