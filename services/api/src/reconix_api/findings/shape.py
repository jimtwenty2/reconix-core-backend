"""The one finding shape every parser's results are turned into, before they are saved."""

import hashlib
from dataclasses import dataclass, field

from reconix_api.models.enums import SeverityStatus


class OutputUnreadable(ValueError):
    """The tool ran, but its output could not be read."""


@dataclass(frozen=True)
class NewEvidence:
    kind: str  # e.g. nmap_port
    content: str  # masked again before it is saved
    location: str  # URL, host:port or file:line


@dataclass(frozen=True)
class NewFinding:
    title: str
    target: str
    description: str
    severity: SeverityStatus
    dedupe_key: str
    evidence: list[NewEvidence] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    owasp_id: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    remediation: str | None = None


def dedupe_key(*parts: str) -> str:
    """The same thing found again, by any tool, gets the same key."""
    text = "|".join(part.strip().lower() for part in parts)
    return hashlib.sha256(text.encode()).hexdigest()
