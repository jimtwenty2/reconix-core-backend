from pathlib import Path

import pytest

from reconix_api.parsers.nmap import NmapParseError, parse

FIXTURE = Path(__file__).parents[2] / "fixtures" / "nmap" / "kali_self_scan.xml"


def test_real_scan_keeps_only_open_ports():
    scan = parse(FIXTURE.read_text())

    [port] = scan.open_ports  # 22 and 80 are closed
    assert port.host == "172.20.0.2"
    assert port.port == 8096
    assert port.protocol == "tcp"
    assert port.service == "http"
    assert port.product == "Uvicorn"
    assert port.cpes == ["cpe:/a:encode:uvicorn"]
    assert port.xml.startswith('<port protocol="tcp" portid="8096">')


def test_probes_are_ports_times_hosts():
    assert parse(FIXTURE.read_text()).probes == 3


def test_host_with_no_open_ports_gives_nothing():
    raw = """<nmaprun><scaninfo numservices="1"/><host><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="filtered"/></port></ports>
    </host></nmaprun>"""
    scan = parse(raw)
    assert scan.open_ports == []
    assert scan.probes == 1


def test_mac_address_is_not_the_host():
    raw = """<nmaprun><host><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <address addr="10.0.0.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="80">
    <state state="open"/></port></ports></host></nmaprun>"""
    [port] = parse(raw).open_ports
    assert port.host == "10.0.0.9"


def test_port_without_portid_is_skipped():
    raw = """<nmaprun><host><address addr="10.0.0.9" addrtype="ipv4"/><ports>
    <port protocol="tcp"><state state="open"/></port></ports></host></nmaprun>"""
    assert parse(raw).open_ports == []


def test_portid_that_is_not_a_number_fails_cleanly():
    raw = """<nmaprun><host><address addr="10.0.0.9" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="abc"><state state="open"/></port></ports></host></nmaprun>"""
    with pytest.raises(NmapParseError, match="BAD_PORT"):
        parse(raw)


@pytest.mark.parametrize("raw", ["", "   ", "not xml at all", "<nmaprun><host>"])
def test_empty_or_broken_output_fails_cleanly(raw):
    with pytest.raises(NmapParseError):
        parse(raw)


def test_truncated_output_fails_cleanly():
    cut = FIXTURE.read_text()[:700] + "\n\n…[truncated: 700 of 2000 bytes shown]"
    with pytest.raises(NmapParseError):
        parse(cut)


def test_other_xml_is_refused():
    with pytest.raises(NmapParseError):
        parse("<report><host/></report>")


def test_entity_expansion_is_refused():
    raw = """<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa">
    <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>"""
    with pytest.raises(NmapParseError):
        parse(raw)
