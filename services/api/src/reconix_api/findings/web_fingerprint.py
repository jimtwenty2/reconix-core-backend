"""whatweb and httpx_probe output -> one technology-fingerprint finding per URL.

What a site runs is a fact, not a weakness, so each finding is NONE. The point is to
record the stack (server, framework, CMS, versions) for the report and for the analysis
step; a weakness in a named version is nuclei's or the analyst's to raise.
"""

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import base_url, host_of, lines, split_top, title
from reconix_api.models.enums import SeverityStatus


def read_whatweb(output: str) -> tuple[list[NewFinding], int]:
    """whatweb text ("URL [200 OK] JQuery[2.2.4], HTML5, ...") -> findings."""
    findings = [_from_whatweb(line) for line in lines(output) if "[" in line]
    kept = [finding for finding in findings if finding is not None]
    if not kept and lines(output):
        raise OutputUnreadable("no whatweb result line")
    return kept, 0


def read_httpx(output: str) -> tuple[list[NewFinding], int]:
    """httpx_probe text ("URL [200] [len] [title] [] [tech,tech]") -> findings."""
    findings = [_from_httpx(line) for line in lines(output) if line.startswith("http")]
    kept = [finding for finding in findings if finding is not None]
    if not kept and lines(output):
        raise OutputUnreadable("no httpx result line")
    return kept, 0


def _from_whatweb(line: str) -> NewFinding | None:
    url, _, rest = line.partition(" ")
    if not url.startswith("http"):
        return None
    plugins = [part for part in split_top(rest) if not part.startswith("[")]
    return _finding(url, plugins, line)


def _from_httpx(line: str) -> NewFinding | None:
    fields = _brackets(line)
    url = line.split(" ", 1)[0]
    tech = split_top(fields[4]) if len(fields) > 4 else []
    name = fields[2] if len(fields) > 2 and fields[2] else ""
    tech = ([f"Title[{name}]"] if name else []) + tech
    return _finding(url, tech, line) if tech else _finding(url, [], line)


def _brackets(line: str) -> list[str]:
    """The contents of each top-level [..] on the line, in order (empty ones kept)."""
    fields, depth, current, inside = [], 0, [], False
    for char in line:
        if char == "[":
            if depth == 0:
                current, inside = [], True
                depth += 1
                continue
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                fields.append("".join(current).strip())
                inside = False
                continue
        if inside:
            current.append(char)
    return fields


def _finding(url: str, items: list[str], raw: str) -> NewFinding:
    where = host_of(url)
    summary = ", ".join(items) if items else "no technologies identified"
    return NewFinding(
        title=title(f"Technology fingerprint: {where}"),
        target=base_url(url),
        description=f"Fingerprinting of {url} identified: {summary}.",
        severity=SeverityStatus.NONE,
        dedupe_key=dedupe_key("web_fingerprint", base_url(url)),
        evidence=[NewEvidence(kind="web_fingerprint", content=raw, location=url)],
    )
