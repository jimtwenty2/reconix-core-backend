"""The code scan tools that give no findings, only a note on the scan.

syft lists the packages it finds (an SBOM, no vulnerabilities): "SYFT 5 packages".
sonar_scan sends its analysis to the SonarQube server inside Kali and returns the text log
of that run: "SONAR_SCAN OK <dashboard URL>" or "SONAR_SCAN FAILED". The masked log stays
on the tool run. tools_info gives the tools' versions: a change makes the next scan full.
"""

import json
import re

from reconix_api.findings.shape import NewFinding, OutputUnreadable

# The scanner's last lines on success; either one means the analysis reached the server.
SONAR_SUCCESS = ("EXECUTION SUCCESS", "ANALYSIS SUCCESSFUL")
APT_TOOLS = ("gitleaks", "trivy", "syft")  # versioned by their Kali package
DASHBOARD = re.compile(r"https?://[^\s\"']+/dashboard\?id=[^\s\"']+")


def read_syft(output: str) -> tuple[list[NewFinding], int]:
    """syft JSON -> no findings. Raises OutputUnreadable when it is not syft's JSON."""
    syft_packages(output)
    return [], 0


def syft_packages(output: str) -> int:
    """How many packages syft found (its "artifacts" list)."""
    try:
        document = json.loads(output or "")
    except json.JSONDecodeError as error:
        raise OutputUnreadable(f"NOT_JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("artifacts"), list):
        raise OutputUnreadable("NOT_SYFT")
    return len(document["artifacts"])


def sonar_dashboard(log: str) -> str | None:
    """The SonarQube dashboard URL the scanner prints on success, if any."""
    match = DASHBOARD.search(log or "")
    return match.group(0) if match else None


def tool_note(tool: str, output: str) -> str | None:
    """The scan note for a COMPLETED run of syft or sonar_scan; None for any other tool."""
    name = str(tool).lower()
    if name == "syft":
        try:
            return f"SYFT {syft_packages(output)} packages"
        except OutputUnreadable:
            return "SYFT OUTPUT_UNREADABLE"
    if name == "sonar_scan":
        if not any(line in (output or "") for line in SONAR_SUCCESS):
            return "SONAR_SCAN FAILED"
        dashboard = sonar_dashboard(output)
        return f"SONAR_SCAN OK {dashboard}" if dashboard else "SONAR_SCAN OK"
    return None


def tool_versions(output: str) -> dict[str, str]:
    """tools_info's JSON -> each code scan tool's version, e.g. {"semgrep": "1.183.0"}.

    Only these lines, never the whole package list, so an unrelated package update does
    not make the next scan a full one. Raises OutputUnreadable when it is not tools_info's."""
    try:
        document = json.loads(output or "")
    except json.JSONDecodeError as error:
        raise OutputUnreadable(f"NOT_JSON: {error}") from error
    versions = document.get("versions") if isinstance(document, dict) else None
    if not isinstance(versions, dict):
        raise OutputUnreadable("NOT_TOOLS_INFO")
    text = {name: value for name, value in versions.items() if isinstance(value, str)}
    found = {}
    for line in text.get("apt", "").splitlines():
        name, _, version = line.partition("\t")
        if name in APT_TOOLS:
            found[name] = version
    for line in text.get("scanners", "").splitlines():
        if line.startswith("semgrep=="):
            found["semgrep"] = line.removeprefix("semgrep==")
    for line in text.get("grype", "").splitlines():
        if line.startswith("Version:"):
            found["grype"] = line.removeprefix("Version:").strip()
    if osv := text.get("osv-scanner", "").strip():
        found["osv_scanner"] = osv.splitlines()[0]
    if sonar := text.get("sonarqube", "").strip():
        found["sonar_scan"] = "\n".join(sonar.splitlines()[:2])  # sonarqube, sonar-scanner
    return found
