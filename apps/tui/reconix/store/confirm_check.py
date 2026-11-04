"""Whether the validation that ran tested the candidate finding it was meant to confirm.

A gated check can be moved with Edit params (another host:port, path or file). A check
that then runs somewhere else proves nothing about the finding: the finding stays
UNCONFIRMED, with a note saying where the check ran instead.

    Host:port  the finding's host and port (10.0.0.1:8443/manager -> 10.0.0.1:8443)
    Path       the finding's path, where {id} stands for one path segment
    File       the same file in the repository
"""

import re
from pathlib import PurePosixPath

from ..models import ApprovalRequest, Finding

ELSEWHERE = (
    "Not collected: the check ran on {where}, not on this finding's own "
    "{what}, so it can't confirm it."
)
WHAT = {"Host:port": "host and port", "Path": "path", "File": "file"}


def _host_port(value: str) -> str:
    """'10.0.0.1:8443' from '10.0.0.1:8443/manager' (lower case, no scheme)."""
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value.strip(), flags=re.IGNORECASE)
    return value.split("/", 1)[0].split("?", 1)[0].casefold()


def _path_matches(pattern: str, path: str) -> bool:
    """'/api/orders/{id}' matches '/api/orders/10483' ({name} is one segment)."""
    parts = re.split(r"(\{[^/{}]*\})", pattern.split("?", 1)[0])
    regex = "".join("[^/]+" if part.startswith("{") else re.escape(part) for part in parts)
    return re.fullmatch(regex, path.split("?", 1)[0]) is not None


def checks_finding(request: ApprovalRequest, finding: Finding) -> bool:
    """Whether `request` (the check that ran) targets `finding`'s own location."""
    label = request.param_label
    if label == "Host:port":
        return _host_port(request.path) == _host_port(finding.path)
    if label == "Path":
        return _path_matches(finding.path, request.path)
    if label == "File":
        return PurePosixPath(request.path) == PurePosixPath(finding.path)
    return True  # nothing editable: the check is the one the plan wrote


def elsewhere_note(request: ApprovalRequest, where: str) -> str:
    """The finding's evidence when the check ran on `where` (already masked) instead."""
    return ELSEWHERE.format(where=where, what=WHAT.get(request.param_label, "location"))
