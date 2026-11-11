"""katana, ffuf and gobuster output -> findings about the paths they found.

These tools can list hundreds of paths, so one path is not one finding. Instead:

- one NONE summary finding per run ("N paths found"), the paths kept as evidence (capped);
- one LOW finding for each path that is sensitive by its name alone (a secret store, a
  backup, a VCS folder, an admin or debug area). LOW, not higher: the name suggests the
  path is worth a look, but whether it is actually exposed or holds anything is for the
  analyst. Severity is never guessed above what the name alone supports.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, dedupe_key
from reconix_api.findings.text import base_url, host_of, lines, title
from reconix_api.models.enums import SeverityStatus

MAX_EVIDENCE = 100  # paths kept on the summary finding's evidence

# A path is flagged only when its name alone says it should not be web-reachable.
SENSITIVE = (
    (re.compile(r"\.(kdbx|key|pem|p12|pfx|jks|keystore|ppk)(/|$)"), "key or credential store"),
    (
        re.compile(r"/(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?(/|$)|/\.ssh(/|$)"),
        "key or credential store",
    ),
    (re.compile(r"/\.git(/|$)"), "version-control folder"),
    (re.compile(r"/\.svn(/|$)"), "version-control folder"),
    (re.compile(r"/\.env(\.|/|$)|/\.env$"), "environment/secrets file"),
    (re.compile(r"/\.(htpasswd|htaccess)(/|$)"), "web-server secret file"),
    (re.compile(r"/\.(bash|sh|mysql|psql|sqlite|zsh)_history(/|$)"), "shell/DB history file"),
    (re.compile(r"\.(bak|old|backup|swp|save|orig)(/|$)"), "backup file"),
    (re.compile(r"\.(sql|dump)(/|$)"), "database dump"),
    (re.compile(r"/(config|configuration|settings)(\.|/|$)"), "configuration"),
    (re.compile(r"/(admin|administrator|administration)(/|$)"), "admin area"),
    (re.compile(r"/(debug|phpinfo|server-status|actuator)(/|$)"), "debug/status endpoint"),
    (re.compile(r"/(ftp|backup|backups|dump)(/|$)"), "exposed file store"),
    (re.compile(r"/(swagger|api-docs|openapi)(\.|/|$)"), "API documentation"),
)

# How bad an exposed path of each kind is by its name alone: a path that leaks a secret, a
# key or source/data is HIGH; an admin, config, backup or debug surface is MEDIUM; anything a
# name only hints at stays LOW. Findings are grouped per kind, not per file.
_SEVERITY = {
    "key or credential store": SeverityStatus.HIGH,
    "environment/secrets file": SeverityStatus.HIGH,
    "web-server secret file": SeverityStatus.HIGH,
    "database dump": SeverityStatus.HIGH,
    "version-control folder": SeverityStatus.HIGH,
    "shell/DB history file": SeverityStatus.MEDIUM,
    "backup file": SeverityStatus.MEDIUM,
    "configuration": SeverityStatus.MEDIUM,
    "admin area": SeverityStatus.MEDIUM,
    "debug/status endpoint": SeverityStatus.MEDIUM,
    "exposed file store": SeverityStatus.MEDIUM,
    "API documentation": SeverityStatus.LOW,
}


def read_katana(output: str) -> tuple[list[NewFinding], int]:
    """katana prints one URL per line."""
    urls = [line for line in lines(output) if line.startswith("http")]
    return _findings(urls, "katana"), 0


def read_ffuf(output: str) -> tuple[list[NewFinding], int]:
    """ffuf default output: "word   [Status: 200, Size: ...]". The word is the found path."""
    return _findings(_fuzz_paths(output), "ffuf"), 0


def read_gobuster(output: str) -> tuple[list[NewFinding], int]:
    """gobuster -q output: "/path   (Status: 200) [Size: ...]"."""
    return _findings(_fuzz_paths(output), "gobuster"), 0


def _fuzz_paths(output: str) -> list[str]:
    """ffuf/gobuster report a bare word ("ftp"); normalise it to a path ("/ftp") so the
    sensitive-name check sees it. A word that is already a path or URL is kept."""
    found = []
    for line in lines(output):
        word = line.split()[0] if line.split() else ""
        if word and "status" in line.lower():
            found.append(word if word.startswith(("/", "http")) else "/" + word)
    return found


def _findings(items: list[str], tool: str) -> list[NewFinding]:
    if not items:
        return []
    where = host_of(items[0]) if items[0].startswith("http") else tool
    base = base_url(items[0]) if items[0].startswith("http") else tool
    evidence = [NewEvidence(kind=f"{tool}_path", content=item, location=item) for item in items]
    summary = NewFinding(
        title=title(f"{len(items)} paths found by {tool} on {where}"),
        target=base,
        description=(
            f"{tool} found {len(items)} path(s). Review them for ones that should not be reachable."
        ),
        severity=SeverityStatus.NONE,
        dedupe_key=dedupe_key("paths_found", tool, base),
        evidence=evidence[:MAX_EVIDENCE],
    )
    sensitive = _grouped_sensitive(items, tool, where)
    return [summary, *sensitive]


def _label(item: str) -> str | None:
    for pattern, label in SENSITIVE:
        if pattern.search(item.lower()):
            return label
    return None


def _grouped_sensitive(items: list[str], tool: str, where: str) -> list[NewFinding]:
    """One finding per kind of sensitive path, not one per file: every path that shares a
    label (a key store, a backup, an exposed /ftp, an admin area) collapses into a single
    finding with the paths as evidence, so 14 /ftp files are one finding, not 14."""
    groups: dict[str, list[str]] = {}
    for item in items:
        label = _label(item)
        if label:
            groups.setdefault(label, []).append(item)
    return [_group_finding(label, paths, tool, where) for label, paths in groups.items()]


def _group_finding(label: str, paths: list[str], tool: str, where: str) -> NewFinding:
    severity = _SEVERITY.get(label, SeverityStatus.LOW)
    first = paths[0]
    target = base_url(first) if first.startswith("http") else where
    count = len(paths)
    shown = ", ".join(paths[:5]) + (" …" if count > 5 else "")
    heading = (
        f"Potentially sensitive path: {first}"
        if count == 1
        else f"{count} potentially sensitive paths ({label}) on {where}"
    )
    return NewFinding(
        title=title(heading),
        target=target,
        description=(
            f"{tool} reported {count} path(s) that look like a {label}: {shown}. "
            "Confirm whether they are reachable and what they expose."
        ),
        severity=severity,
        dedupe_key=dedupe_key("sensitive_group", where, label),
        evidence=[
            NewEvidence(kind=f"{tool}_path", content=p, location=p) for p in paths[:MAX_EVIDENCE]
        ],
        owasp_id=["A01:2021"],
        remediation="Remove the path from the web root or restrict who can reach it.",
    )
