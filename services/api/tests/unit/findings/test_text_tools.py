"""Readers for the text tools (whatweb, httpx, katana, ffuf, gobuster, testssl, nikto,
dalfox). Fixtures are real output captured from these tools in the lab Kali container
against the lab target only (testssl against a throwaway local TLS server; dalfox against
a throwaway local reflector), see each fixture's folder."""

from pathlib import Path

import pytest

from reconix_api.models.enums import SeverityStatus
from reconix_api.services.findings import parse_run

FIXTURES = Path(__file__).parents[2] / "fixtures"


def load(tool: str, name: str) -> str:
    return (FIXTURES / tool / name).read_text(encoding="utf-8")


# --- whatweb / httpx: one NONE fingerprint finding per URL ----------------------------


def test_whatweb_one_none_finding_with_the_stack():
    findings, requests = parse_run("whatweb", load("whatweb", "juice_shop.txt"))
    assert requests == 0
    [finding] = findings
    assert finding.severity == SeverityStatus.NONE
    assert finding.target == "http://juice-shop:3000"
    assert "JQuery[2.2.4]" in finding.evidence[0].content


def test_httpx_one_none_finding_with_the_stack():
    [finding] = parse_run("httpx_probe", load("httpx", "juice_shop.txt"))[0]
    assert finding.severity == SeverityStatus.NONE
    assert "jQuery:2.2.4" in finding.description or "jQuery:2.2.4" in finding.evidence[0].content


def test_two_fingerprints_of_the_same_site_dedupe():
    one = parse_run("whatweb", load("whatweb", "juice_shop.txt"))[0][0]
    two = parse_run("httpx_probe", load("httpx", "juice_shop.txt"))[0][0]
    assert one.dedupe_key == two.dedupe_key  # same site, same finding


# --- katana / ffuf / gobuster: one NONE summary + LOW per sensitive path ---------------


def test_katana_makes_one_summary_finding():
    findings, _ = parse_run("katana", load("katana", "juice_shop.txt"))
    summary = findings[0]
    assert summary.severity == SeverityStatus.NONE
    assert "paths found by katana" in summary.title
    assert len(summary.evidence) >= 1


def test_ffuf_flags_the_ftp_path_as_low():
    findings, _ = parse_run("ffuf", load("ffuf", "juice_shop.txt"))
    assert findings[0].severity == SeverityStatus.NONE  # summary first
    sensitive = [f for f in findings if f.severity == SeverityStatus.LOW]
    assert any("ftp" in f.title.lower() for f in sensitive)
    assert all(f.owasp_id == ["A01:2021"] for f in sensitive)


def test_gobuster_summary_counts_every_path():
    findings, _ = parse_run("gobuster", load("gobuster", "juice_shop.txt"))
    assert "6 paths found" in findings[0].title


def test_a_boring_path_makes_no_extra_finding():
    findings, _ = parse_run("gobuster", "assets   (Status: 301) [Size: 156]\n")
    assert len(findings) == 1  # only the summary
    assert findings[0].severity == SeverityStatus.NONE


# --- testssl: severity only from testssl's own words -----------------------------------


def test_testssl_flags_deprecated_protocols_medium():
    findings, _ = parse_run("testssl", load("testssl", "local_tls.txt"))
    deprecated = [f for f in findings if "offered" in f.description.lower()]
    assert deprecated and all(f.severity == SeverityStatus.MEDIUM for f in deprecated)


def test_testssl_keeps_cve_on_a_vulnerable_line():
    # LUCKY13 is the single-line vulnerability case: label, CVE and verdict on one line.
    # (BEAST's verdict wraps onto a later line from its CVE; multi-line attribution is a
    # known limit, noted in the reader.)
    findings, _ = parse_run("testssl", load("testssl", "local_tls.txt"))
    lucky = next(f for f in findings if "LUCKY13" in f.title)
    assert "CVE-2013-0169" in lucky.cve_ids


def test_testssl_makes_no_finding_for_ok_lines():
    findings, _ = parse_run("testssl", load("testssl", "local_tls.txt"))
    assert all("not vulnerable" not in f.description.lower() for f in findings)


def test_testssl_self_signed_cert_is_low():
    findings, _ = parse_run("testssl", load("testssl", "local_tls.txt"))
    cert = [f for f in findings if f.severity == SeverityStatus.LOW]
    assert any("self signed" in f.evidence[0].content.lower() for f in cert)


# --- nikto: UNKNOWN by default, LOW for a missing header -------------------------------


def test_nikto_items_default_to_unknown():
    findings, _ = parse_run("nikto", load("nikto", "juice_shop.txt"))
    assert findings
    assert any(f.severity == SeverityStatus.UNKNOWN for f in findings)


def test_nikto_missing_security_header_is_low():
    findings, _ = parse_run("nikto", load("nikto", "juice_shop.txt"))
    headers = [f for f in findings if "security header missing" in f.description.lower()]
    assert headers and all(f.severity == SeverityStatus.LOW for f in headers)


def test_nikto_drops_summary_lines():
    findings, _ = parse_run("nikto", load("nikto", "juice_shop.txt"))
    assert all("requests:" not in f.title for f in findings)


# --- dalfox: verified XSS is HIGH with CWE-79 ------------------------------------------


def test_dalfox_verified_xss_is_high():
    findings, _ = parse_run("dalfox", load("dalfox", "reflector_xss.txt"))
    [finding] = findings
    assert finding.severity == SeverityStatus.HIGH
    assert finding.cwe_ids == ["CWE-79"]
    assert finding.owasp_id == ["A03:2021"]


def test_dalfox_clean_scan_makes_no_finding():
    clean = "2:11AM INF start scan\n2:11AM WRN XSS found 0 XSS\n"
    findings, _ = parse_run("dalfox", clean)
    assert findings == []


# --- unreadable output -----------------------------------------------------------------


@pytest.mark.parametrize("tool", ["testssl", "nikto", "dalfox"])
def test_wrong_output_is_unreadable_not_a_crash(tool):
    from reconix_api.findings.shape import OutputUnreadable

    with pytest.raises(OutputUnreadable):
        parse_run(tool, "this is not that tool's output at all")


# --- schemathesis / enum4linux / onesixtyone / sqlmap: API, SMB, SNMP, SQLi ------------
# Fixtures are real output captured in the lab Kali container: schemathesis against the
# lab VAmPI API, enum4linux against the lab metasploitable host, onesixtyone silent (no
# SNMP there), sqlmap against a lab VAmPI parameter. See each fixture folder.


def test_schemathesis_server_error_is_medium_the_rest_low():
    findings, requests = parse_run("schemathesis", load("schemathesis", "vampi.txt"))
    assert requests == 0 and findings
    server_errors = [f for f in findings if f.severity == SeverityStatus.MEDIUM]
    assert server_errors, "the 500 (ST101) should be MEDIUM"
    assert all("ST101" in e.content for f in server_errors for e in f.evidence)
    # the contract checks (undocumented status/content-type, schema) are LOW
    assert any(f.severity == SeverityStatus.LOW for f in findings)
    # one finding per (operation, check) — no duplicate keys
    keys = [f.dedupe_key for f in findings]
    assert len(keys) == len(set(keys))


def test_enum4linux_null_session_is_medium():
    findings, _ = parse_run("enum4linux", load("enum4linux", "metasploitable.txt"))
    null = [f for f in findings if "null session" in f.title.lower()]
    assert null and null[0].severity == SeverityStatus.MEDIUM
    assert null[0].cwe_ids == ["CWE-287"]


def test_onesixtyone_silent_host_makes_no_finding():
    findings, _ = parse_run("onesixtyone", load("onesixtyone", "silent.txt"))
    assert findings == []


def test_onesixtyone_responding_community_is_medium():
    sample = "Scanning 1 hosts, 1 communities\n10.0.0.5 [public] Linux metasploitable 2.6.24\n"
    [finding] = parse_run("onesixtyone", sample)[0]
    assert finding.severity == SeverityStatus.MEDIUM
    assert "public" in finding.title and finding.target == "10.0.0.5"


def test_sqlmap_confirmed_injection_is_high():
    findings, _ = parse_run("sqlmap", load("sqlmap", "vampi.txt"))
    assert findings
    assert all(f.severity == SeverityStatus.HIGH for f in findings)
    assert all(f.cwe_ids == ["CWE-89"] for f in findings)
    assert any("SQLite" in f.description for f in findings)


def test_sqlmap_no_injection_makes_no_finding():
    clean = "sqlmap resumed the following\nall tested parameters do not appear to be injectable.\n"
    findings, _ = parse_run("sqlmap", clean)
    assert findings == []


@pytest.mark.parametrize("tool", ["schemathesis", "enum4linux", "onesixtyone", "sqlmap"])
def test_new_readers_reject_wrong_output(tool):
    from reconix_api.findings.shape import OutputUnreadable

    with pytest.raises(OutputUnreadable):
        parse_run(tool, "this is not that tool's output at all")
