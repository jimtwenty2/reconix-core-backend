"""The 7 code scan tools on real Kali output (reconix-kali-container, Nov 2026).

The probe folder held app.py (SQL injection, SECRET_KEY, debug=True) in tests/, settings.py
with a fake GitHub token, requirements.txt (flask 0.12.2, requests 2.19.0, pyjwt 1.5.0) and
package-lock.json (lodash 4.17.4). The folder is renamed to a fixed fake session id;
gitleaks ran with --redact, and the one private key an osv advisory quotes is removed.
"""

import json
from pathlib import Path

import pytest

from reconix_ai.harness import mask_secrets
from reconix_api.core.masking import mask_output
from reconix_api.findings import code_notes
from reconix_api.findings.shape import OutputUnreadable, dedupe_key
from reconix_api.models.enums import SeverityStatus
from reconix_api.services.findings import parse_run

FIX = Path(__file__).parents[2] / "fixtures"
ROOT = "/workspace/code/11111111-1111-4111-8111-111111111111"
REQUIREMENTS = f"{ROOT}/requirements.txt"
LOCKFILE = f"{ROOT}/package-lock.json"


def probe(tool: str, name: str = "kali_probe.json") -> str:
    return (FIX / tool / name).read_text()


def masked(tool: str, name: str = "kali_probe.json") -> str:
    """As tool_runs saves it: the parsers only ever see the masked output."""
    return mask_output(mask_secrets, probe(tool, name))[0]


def test_semgrep_finds_the_four_issues_in_tests_folder():
    found, _ = parse_run("semgrep", masked("semgrep"))
    assert {f.target for f in found} == {f"{ROOT}/tests/test_app.py"}
    rules = {f.title.rsplit(".", 1)[-1]: f.severity for f in found}
    assert rules == {
        "avoid_hardcoded_config_SECRET_KEY": SeverityStatus.HIGH,  # ERROR
        "formatted-sql-query": SeverityStatus.MEDIUM,  # WARNING
        "sqlalchemy-execute-raw-query": SeverityStatus.HIGH,
        "debug-enabled": SeverityStatus.MEDIUM,
    }


@pytest.mark.parametrize(
    ("word", "severity"),
    [
        ("CRITICAL", SeverityStatus.CRITICAL),
        ("HIGH", SeverityStatus.HIGH),
        ("MEDIUM", SeverityStatus.MEDIUM),
        ("LOW", SeverityStatus.LOW),
        ("INFO", SeverityStatus.LOW),  # semgrep's own INFO stays LOW, not NONE
        ("ERROR", SeverityStatus.HIGH),
        ("SOMETHING", SeverityStatus.UNKNOWN),
    ],
)
def test_semgrep_reads_old_and_new_severity_words(word, severity):
    result = {"check_id": "r", "path": "a.py", "start": {"line": 1}, "extra": {"severity": word}}
    [finding], _ = parse_run("semgrep", json.dumps({"results": [result]}))
    assert finding.severity == severity


def test_gitleaks_leak_is_high_and_keeps_no_secret():
    [leak], _ = parse_run("gitleaks", masked("gitleaks"))
    assert leak.severity == SeverityStatus.HIGH
    assert leak.target == f"{ROOT}/settings.py"
    assert leak.evidence[0].location == f"{ROOT}/settings.py:1"
    assert not {"Secret", "Match"} & json.loads(leak.evidence[0].content).keys()


def test_trivy_target_is_the_manifest_from_the_parent_result():
    found, _ = parse_run("trivy", masked("trivy"))
    assert len(found) == 28
    assert {f.target for f in found} == {REQUIREMENTS, LOCKFILE}
    lodash = [f for f in found if f.evidence[0].location.startswith("lodash:")]
    assert lodash and {f.target for f in lodash} == {LOCKFILE}
    proof = json.loads(lodash[0].evidence[0].content)
    # the dedupe key is the vulnerability, the package and the manifest
    assert lodash[0].dedupe_key == dedupe_key(
        "trivy_vulnerability", proof["VulnerabilityID"], "lodash", "4.17.4", LOCKFILE
    )


def test_one_package_in_two_manifests_is_two_findings():
    vulnerability = {
        "VulnerabilityID": "CVE-2018-1",
        "PkgName": "requests",
        "InstalledVersion": "2",
    }
    trivy = {
        "ArtifactName": ROOT,
        "ArtifactType": "filesystem",
        "Results": [
            {"Target": "svc-a/requirements.txt", "Vulnerabilities": [vulnerability]},
            {"Target": "svc-b/requirements.txt", "Vulnerabilities": [vulnerability]},
        ],
    }
    match = {
        "vulnerability": {"id": "CVE-2018-1"},
        "artifact": {"name": "requests", "version": "2"},
    }
    grype = {
        "source": {"type": "directory", "target": ROOT},
        "matches": [
            {**match, "artifact": {**match["artifact"], "locations": [{"path": f"/{name}"}]}}
            for name in ("svc-a/requirements.txt", "svc-b/requirements.txt")
        ],
    }
    package = {"package": {"name": "requests", "version": "2"}, "vulnerabilities": [{"id": "X"}]}
    osv = {
        "results": [
            {"source": {"path": f"{ROOT}/{name}"}, "packages": [package]}
            for name in ("svc-a/requirements.txt", "svc-b/requirements.txt")
        ]
    }
    for tool, output in (("trivy", trivy), ("grype", grype), ("osv_scanner", osv)):
        found, _ = parse_run(tool, json.dumps(output))
        assert len({f.dedupe_key for f in found}) == 2, tool
        assert sorted(f.target for f in found) == [
            f"{ROOT}/svc-a/requirements.txt",
            f"{ROOT}/svc-b/requirements.txt",
        ]


def test_trivy_on_an_image_keeps_the_package_as_target():
    vulnerability = {"VulnerabilityID": "CVE-2024-1", "PkgName": "musl", "InstalledVersion": "1"}
    document = {
        "ArtifactName": "alpine:3.10",
        "ArtifactType": "container_image",
        "Results": [{"Target": "alpine:3.10 (alpine 3.10.2)", "Vulnerabilities": [vulnerability]}],
    }
    [finding], _ = parse_run("trivy", json.dumps(document))
    assert finding.target == "musl"
    # no manifest: the key is the vulnerability and the package, as before
    assert finding.dedupe_key == dedupe_key("trivy_vulnerability", "CVE-2024-1", "musl", "1")


def test_trivy_relative_folder_gives_a_relative_manifest():
    # the older fixture was run as "trivy fs ." : ArtifactName "."
    found, _ = parse_run("trivy", probe("trivy", "vulnerable_app.json"))
    assert [f.target for f in found] == ["requirements.txt", "requirements.txt"]


def test_grype_target_is_the_folder_plus_the_package_location():
    found, _ = parse_run("grype", masked("grype"))
    assert len(found) == 29
    assert {f.target for f in found} == {REQUIREMENTS, LOCKFILE}


@pytest.mark.parametrize(
    ("source", "locations"),
    [
        ({"type": "image", "target": {"userInput": "alpine:3.10"}}, [{"path": "/lib/apk/db"}]),
        ({"type": "directory", "target": ROOT}, []),
    ],
)
def test_grype_without_a_folder_location_keeps_the_package_as_target(source, locations):
    match = {
        "vulnerability": {"id": "CVE-2024-1"},
        "artifact": {"name": "musl", "version": "1", "locations": locations},
    }
    [finding], _ = parse_run("grype", json.dumps({"source": source, "matches": [match]}))
    assert finding.target == "musl"


def test_osv_target_is_its_absolute_source_path():
    found, _ = parse_run("osv_scanner", masked("osv"))
    assert len(found) == 79
    assert {f.target for f in found} == {REQUIREMENTS, LOCKFILE}


@pytest.mark.parametrize("tool", ["trivy", "grype"])
def test_dependency_readers_refuse_broken_output(tool):
    for output in ("", "not json", "[]"):
        with pytest.raises(OutputUnreadable):
            parse_run(tool, output)


def test_syft_gives_no_findings_and_a_package_count_note():
    output = masked("syft")
    assert parse_run("syft", output) == ([], 0)
    assert code_notes.tool_note("SYFT", output) == "SYFT 5 packages"


def test_syft_output_that_is_not_syft_is_unreadable():
    with pytest.raises(OutputUnreadable):
        parse_run("syft", '{"matches": []}')
    assert code_notes.tool_note("SYFT", "not json") == "SYFT OUTPUT_UNREADABLE"


def test_sonar_log_gives_no_findings_and_an_ok_note_with_the_dashboard():
    log = masked("sonar_scan", "kali_probe.log")
    assert parse_run("sonar_scan", log) == ([], 0)
    assert (
        code_notes.tool_note("SONAR_SCAN", log)
        == "SONAR_SCAN OK http://localhost:9000/dashboard?id=probe"
    )


@pytest.mark.parametrize(
    ("log", "note"),
    [
        ("INFO  EXECUTION SUCCESS\n", "SONAR_SCAN OK"),  # success, no dashboard line
        ("ERROR Error during SonarScanner execution\nINFO  EXECUTION FAILURE\n", None),
        ("", None),
    ],
)
def test_sonar_note_without_success_is_failed(log, note):
    assert code_notes.tool_note("sonar_scan", log) == (note or "SONAR_SCAN FAILED")


def test_other_tools_get_no_note():
    assert code_notes.tool_note("SEMGREP", probe("semgrep")) is None


def test_tools_info_gives_only_the_code_scan_tools_versions():
    assert code_notes.tool_versions(probe("tools_info")) == {
        "gitleaks": "8.26.0-1+b1",
        "trivy": "0.66.0-0kali1",
        "syft": "1.51.0+ds-0kali1",
        "semgrep": "1.183.0",
        "grype": "0.120.1",
        "osv_scanner": "osv-scanner version: 2.7.0",
        "sonar_scan": "sonarqube 24.12.0.100206\nsonar-scanner 8.1.0.6389",
    }


@pytest.mark.parametrize("output", ["", "not json", "[]", '{"tools": []}', '{"versions": "x"}'])
def test_tools_info_without_versions_is_unreadable(output):
    with pytest.raises(OutputUnreadable):
        code_notes.tool_versions(output)


def test_tools_info_with_none_of_the_tools_gives_no_versions():
    output = json.dumps({"versions": {"apt": "zsh\t5.9\n", "newman": "6"}})
    assert code_notes.tool_versions(output) == {}
