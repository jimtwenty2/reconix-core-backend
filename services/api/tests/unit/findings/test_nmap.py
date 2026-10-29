from pathlib import Path

import pytest

from reconix_api.findings.nmap import read, to_findings
from reconix_api.findings.shape import OutputUnreadable, dedupe_key
from reconix_api.models.enums import SeverityStatus
from reconix_api.parsers.nmap import NmapScan, OpenPort

FIXTURE = Path(__file__).parents[2] / "fixtures" / "nmap" / "kali_self_scan.xml"


def port(**fields) -> OpenPort:
    base = {
        "host": "172.20.0.5",
        "hostname": "juice-shop",
        "port": 3000,
        "protocol": "tcp",
        "service": "http",
        "product": "Node.js Express",
        "version": None,
        "extra_info": None,
        "xml": '<port protocol="tcp" portid="3000"/>',
    }
    return OpenPort(**{**base, **fields})


def test_one_finding_per_open_port():
    [finding] = to_findings(NmapScan(open_ports=[port()], probes=1))
    assert finding.title == "Open port 3000/tcp (http, Node.js Express)"
    assert finding.target == "172.20.0.5"
    assert "juice-shop" in finding.description
    [evidence] = finding.evidence
    assert evidence.kind == "nmap_port"
    assert evidence.location == "172.20.0.5:3000/tcp"


def test_an_open_port_is_not_a_weakness():
    [finding] = to_findings(NmapScan(open_ports=[port()], probes=1))
    assert finding.severity == SeverityStatus.NONE


def test_dedupe_key_ignores_the_service_name():
    first = to_findings(NmapScan(open_ports=[port()], probes=1))[0]
    again = to_findings(NmapScan(open_ports=[port(service="ppp", product=None)], probes=1))[0]
    assert first.dedupe_key == again.dedupe_key


def test_dedupe_key_differs_by_host_port_and_protocol():
    keys = {
        to_findings(NmapScan(open_ports=[p], probes=1))[0].dedupe_key
        for p in (port(), port(host="172.20.0.6"), port(port=22), port(protocol="udp"))
    }
    assert len(keys) == 4


def test_dedupe_key_is_stable_and_fits_the_column():
    key = dedupe_key("open_port", "172.20.0.5", "3000", "tcp")
    assert key == dedupe_key("OPEN_PORT", " 172.20.0.5 ", "3000", "TCP")
    assert len(key) <= 255


def test_bare_port_without_service():
    [finding] = to_findings(NmapScan(open_ports=[port(service=None, product=None)], probes=1))
    assert finding.title == "Open port 3000/tcp"


def test_read_gives_findings_and_probes():
    found, probes = read(FIXTURE.read_text())
    assert [f.title for f in found] == ["Open port 8096/tcp (http, Uvicorn)"]
    assert probes == 3


def test_read_of_broken_output_is_unreadable():
    with pytest.raises(OutputUnreadable):
        read("<nmaprun><host>")
