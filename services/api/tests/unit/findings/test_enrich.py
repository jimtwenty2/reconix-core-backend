"""A later, richer occurrence of the same finding upgrades the stored one in place.

The case this guards: a plain `nmap -p` run saves "Open port 21/tcp (ftp)", then an
`nmap -sV` run finds the same port with the version. They share a dedupe_key, so the
second only adds a source — unless the stored finding is upgraded, the version is lost.
"""

from reconix_api.findings.shape import NewEvidence, NewFinding, dedupe_key
from reconix_api.models.enums import SeverityStatus
from reconix_api.models.finding import Finding
from reconix_api.services.findings import _enrich, _more_detailed


def _identity(text: str) -> tuple[str, int]:
    return text, 0


def _stored(title: str, description: str, **kw) -> Finding:
    return Finding(
        code="RCX-001",
        title=title,
        target="10.0.0.5",
        description=description,
        severity_status=SeverityStatus.NONE,
        dedupe_key=dedupe_key("open_port", "10.0.0.5", "21", "tcp"),
        cve_ids=kw.get("cve_ids", []),
        cwe_ids=kw.get("cwe_ids", []),
        owasp_id=kw.get("owasp_id", []),
        remediation=kw.get("remediation"),
    )


def _richer() -> NewFinding:
    return NewFinding(
        title="Open port 21/tcp (ftp, vsftpd 2.3.4)",
        target="10.0.0.5",
        description="nmap found port 21/tcp open on 10.0.0.5. Service: ftp, vsftpd 2.3.4.",
        severity=SeverityStatus.NONE,
        dedupe_key=dedupe_key("open_port", "10.0.0.5", "21", "tcp"),
        evidence=[NewEvidence(kind="nmap_port", content="<port/>", location="10.0.0.5:21/tcp")],
        cve_ids=["CVE-2011-2523"],
    )


def test_a_richer_later_occurrence_upgrades_title_and_description():
    finding = _stored("Open port 21/tcp (ftp)", "nmap found port 21/tcp open on 10.0.0.5.")
    _enrich(_identity, finding, _richer())
    assert finding.title == "Open port 21/tcp (ftp, vsftpd 2.3.4)"
    assert "vsftpd 2.3.4" in finding.description
    assert finding.cve_ids == ["CVE-2011-2523"]
    assert finding.severity_status is SeverityStatus.NONE  # never changed


def test_an_equal_or_less_detailed_occurrence_changes_nothing():
    finding = _stored(
        "Open port 21/tcp (ftp, vsftpd 2.3.4)",
        "nmap found port 21/tcp open on 10.0.0.5. Service: ftp, vsftpd 2.3.4.",
    )
    before = (finding.title, finding.description)
    # A later bare scan of the same port: shorter title, same key.
    plain = NewFinding(
        title="Open port 21/tcp (ftp)",
        target="10.0.0.5",
        description="nmap found port 21/tcp open on 10.0.0.5.",
        severity=SeverityStatus.NONE,
        dedupe_key=finding.dedupe_key,
    )
    _enrich(_identity, finding, plain)
    assert (finding.title, finding.description) == before  # no downgrade


def test_ids_are_merged_without_duplicates():
    finding = _stored("Open port 21/tcp (ftp)", "x", cve_ids=["CVE-2011-2523"])
    item = _richer()  # also carries CVE-2011-2523
    _enrich(_identity, finding, item)
    assert finding.cve_ids == ["CVE-2011-2523"]  # union, no duplicate


def test_more_detailed_rule():
    assert _more_detailed("Open port 21/tcp (ftp)", "Open port 21/tcp (ftp, vsftpd 2.3.4)")
    assert not _more_detailed("Open port 21/tcp (ftp, vsftpd 2.3.4)", "Open port 21/tcp (ftp)")
    assert not _more_detailed("same", "same")
    assert not _more_detailed("totally", "different text")  # new must contain old
