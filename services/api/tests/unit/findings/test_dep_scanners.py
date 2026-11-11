"""trivy, grype and osv-scanner on real output: a Python requirements.txt with old,
vulnerable pins (flask 0.12, pyyaml 5.3, requests 2.19, jinja2 2.10). Fixtures were captured
from the tools run once with their vulnerability databases."""

from collections import Counter
from pathlib import Path

from reconix_api.findings.shape import NewFinding
from reconix_api.models.enums import SeverityStatus
from reconix_api.services.findings import parse_run

FIX = Path(__file__).parents[2] / "fixtures"
TRIVY = (FIX / "trivy" / "lab_requirements.json").read_text()
GRYPE = (FIX / "grype" / "lab_requirements.json").read_text()
OSV = (FIX / "osv" / "lab_requirements.json").read_text()
MANIFEST = "/workspace/code/leak-repo/requirements.txt"

SEVERITIES = {
    SeverityStatus.CRITICAL,
    SeverityStatus.HIGH,
    SeverityStatus.MEDIUM,
    SeverityStatus.LOW,
}


def package(finding: NewFinding) -> str:
    """The package name from the evidence location: "flask:0.12" or "flask@0.12 (path)"."""
    return finding.evidence[0].location.split("@")[0].split(":")[0]


def test_trivy_reads_iac_misconfigurations_alongside_vulnerabilities():
    misconfig = (FIX / "trivy" / "misconfig.json").read_text()
    findings, _ = parse_run("trivy", misconfig)
    kinds = [f.evidence[0].kind for f in findings]
    # A dependency vuln and an IaC misconfig coexist in one trivy run.
    assert "trivy_vulnerability" in kinds and "trivy_misconfig" in kinds
    mis = [f for f in findings if f.evidence[0].kind == "trivy_misconfig"]
    assert len(mis) == 1  # only the FAILED check, not the PASS one
    assert mis[0].severity == SeverityStatus.HIGH
    assert mis[0].target == "/workspace/code/s1/Dockerfile"
    assert "root" in mis[0].title.lower()
    assert mis[0].remediation and "USER" in mis[0].remediation


def test_trivy_reads_every_vulnerability():
    findings, requests = parse_run("trivy", TRIVY)
    assert len(findings) == 17 and requests == 0
    flask = next(f for f in findings if "CVE-2018-1000656" in f.cve_ids)
    assert flask.target == MANIFEST
    assert package(flask) == "flask"
    assert flask.severity == SeverityStatus.HIGH
    assert flask.cwe_ids == ["CWE-20"]
    assert all(f.severity in SEVERITIES for f in findings)
    assert all(f.evidence[0].kind == "trivy_vulnerability" for f in findings)


def test_grype_reads_matches_with_cwe_and_severity():
    findings, requests = parse_run("grype", GRYPE)
    assert findings and requests == 0
    assert {f.target for f in findings} == {MANIFEST}
    pyyaml = next(f for f in findings if package(f) == "pyyaml")
    assert pyyaml.severity == SeverityStatus.CRITICAL  # GHSA-8q59-q68h-6hv4
    assert "CWE-20" in pyyaml.cwe_ids
    assert "CVE-2020-14343" in pyyaml.cve_ids  # pulled from the cwes entries
    assert all(f.severity in SEVERITIES for f in findings)
    assert all(f.evidence[0].kind == "grype_vulnerability" for f in findings)


def test_osv_reads_severity_from_the_group_and_cve_from_aliases():
    findings, requests = parse_run("osv_scanner", OSV)
    assert findings and requests == 0
    flask = next(f for f in findings if "PYSEC-2018-66" in f.evidence[0].content)
    assert flask.target == MANIFEST
    assert package(flask) == "flask"
    assert flask.severity == SeverityStatus.HIGH  # group max_severity 8.7
    assert "CVE-2018-1000656" in flask.cve_ids  # from aliases
    assert (
        flask.dedupe_key
        == next(f for f in parse_run("osv_scanner", OSV)[0] if package(f) == "flask").dedupe_key
    )


def test_the_three_tools_find_the_same_vulnerable_packages():
    packages = {}
    for tool, output in (("trivy", TRIVY), ("grype", GRYPE), ("osv_scanner", OSV)):
        packages[tool] = {package(f) for f in parse_run(tool, output)[0]}
    # flask, pyyaml, jinja2 and requests are all old and vulnerable; every tool sees them.
    for tool, found in packages.items():
        assert {"flask", "pyyaml"} <= found, (tool, found)


def test_the_three_tools_share_one_dedupe_key_for_the_same_cve():
    # The same CVE in the same package+file must collapse to one finding (each tool a source)
    # at save time, not three — despite GHSA-vs-CVE ids and 5.3-vs-5.3.0 version formats.
    keys = set()
    for tool, output in (("trivy", TRIVY), ("grype", GRYPE), ("osv_scanner", OSV)):
        findings, _ = parse_run(tool, output)
        hit = [f for f in findings if "CVE-2020-14343" in f.cve_ids]
        assert hit, f"{tool} did not surface CVE-2020-14343 for pyyaml"
        keys.update(f.dedupe_key for f in hit)
    assert len(keys) == 1, keys


def test_severity_spread_is_real_not_all_unknown():
    for output, tool in ((TRIVY, "trivy"), (GRYPE, "grype"), (OSV, "osv_scanner")):
        counts = Counter(f.severity for f in parse_run(tool, output)[0])
        assert counts[SeverityStatus.UNKNOWN] == 0, (tool, counts)
