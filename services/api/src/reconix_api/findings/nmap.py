"""nmap open ports -> findings. One finding per open port on a host.

An open port is a fact, not a weakness, so its severity is NONE. Weaknesses on
that port come from nuclei and ZAP, and get their own findings.
"""

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.models.enums import SeverityStatus
from reconix_api.parsers.nmap import NmapParseError, NmapScan, OpenPort, parse


def read(output: str) -> tuple[list[NewFinding], int]:
    """Masked nmap XML -> (findings, probes sent)."""
    try:
        scan = parse(output)
    except NmapParseError as error:
        raise OutputUnreadable(str(error)) from error
    return to_findings(scan), scan.probes


def to_findings(scan: NmapScan) -> list[NewFinding]:
    return [_finding(port) for port in scan.open_ports]


def _finding(port: OpenPort) -> NewFinding:
    where = f"{port.host}:{port.port}/{port.protocol}"
    service = _service(port)
    return NewFinding(
        title=f"Open port {port.port}/{port.protocol}" + (f" ({service})" if service else ""),
        target=port.host,
        description=_description(port, service),
        severity=SeverityStatus.NONE,
        dedupe_key=dedupe_key("open_port", port.host, str(port.port), port.protocol),
        evidence=[NewEvidence(kind="nmap_port", content=port.xml, location=where)],
        remediation="Close the port or limit who can reach it if the service is not needed.",
    )


def _service(port: OpenPort) -> str:
    """e.g. "http, Uvicorn 0.34"."""
    product = " ".join(part for part in (port.product, port.version) if part)
    return ", ".join(part for part in (port.service, product) if part)


def _description(port: OpenPort, service: str) -> str:
    host = f"{port.host} ({port.hostname})" if port.hostname else port.host
    text = f"nmap found port {port.port}/{port.protocol} open on {host}."
    if service:
        text += f" Service: {service}."
    if port.extra_info:
        text += f" Details: {port.extra_info}."
    if port.cpes:
        text += f" CPE: {', '.join(port.cpes)}."
    return text
