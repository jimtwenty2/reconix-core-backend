"""nmap XML (-oX -) -> the open ports it found. Only reads; no database, no HTTP.

The XML holds text the scanned host chose (banners, hostnames), so it is read with
defusedxml, which refuses entity tricks.
"""

from dataclasses import dataclass, field
from xml.etree.ElementTree import Element, ParseError, tostring

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring


class NmapParseError(ValueError):
    """The output is empty, cut off or not nmap XML."""


@dataclass(frozen=True)
class OpenPort:
    host: str  # the IP address
    hostname: str | None
    port: int
    protocol: str  # tcp or udp
    service: str | None  # e.g. http
    product: str | None  # e.g. Uvicorn
    version: str | None
    extra_info: str | None
    cpes: list[str] = field(default_factory=list)
    xml: str = ""  # the <port> element, as proof


@dataclass(frozen=True)
class NmapScan:
    open_ports: list[OpenPort]
    probes: int  # ports asked about x hosts scanned: at least one probe each


def parse(raw: str) -> NmapScan:
    if not raw or not raw.strip():
        raise NmapParseError("EMPTY_OUTPUT")
    try:
        root = fromstring(raw)
    except (ParseError, DefusedXmlException) as error:
        raise NmapParseError(f"NOT_NMAP_XML: {error}") from error
    if root.tag != "nmaprun":
        raise NmapParseError("NOT_NMAP_XML: root is not <nmaprun>")

    hosts = root.findall("host")
    open_ports = [port for host in hosts for port in _open_ports(host)]
    return NmapScan(open_ports=open_ports, probes=_services_per_host(root) * len(hosts))


def _open_ports(host: Element) -> list[OpenPort]:
    address = _address(host)
    if address is None:
        return []
    hostname_node = host.find("hostnames/hostname")
    hostname = hostname_node.get("name") if hostname_node is not None else None
    ports = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        number = _port_number(port)
        if state is None or state.get("state") != "open" or number is None:
            continue
        service = port.find("service")
        ports.append(
            OpenPort(
                host=address,
                hostname=hostname,
                port=number,
                protocol=port.get("protocol", "tcp"),
                service=_attr(service, "name"),
                product=_attr(service, "product"),
                version=_attr(service, "version"),
                extra_info=_attr(service, "extrainfo"),
                cpes=[cpe.text for cpe in port.findall("service/cpe") if cpe.text],
                xml=tostring(port, encoding="unicode").strip(),
            )
        )
    return ports


def _port_number(port: Element) -> int | None:
    """The portid; None when it is missing. Not a number: the output is broken."""
    portid = port.get("portid")
    if portid is None:
        return None
    if not portid.isdigit():
        raise NmapParseError(f"BAD_PORT: {portid[:20]!r}")
    return int(portid)


def _address(host: Element) -> str | None:
    """The IPv4 or IPv6 address; never the MAC address."""
    for node in host.findall("address"):
        if node.get("addrtype") in ("ipv4", "ipv6"):
            return node.get("addr")
    return None


def _attr(node: Element | None, name: str) -> str | None:
    return node.get(name) if node is not None else None


def _services_per_host(root: Element) -> int:
    return sum(int(info.get("numservices", "0")) for info in root.findall("scaninfo"))
