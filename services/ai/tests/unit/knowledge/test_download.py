import io
import zipfile

import httpx
import pytest

from reconix_ai.knowledge import download
from reconix_ai.knowledge.download import (
    fetch,
    first_heading,
    parse_attack,
    parse_cwe,
    parse_kev,
    unzip_one_xml,
)
from reconix_ai.knowledge.items import Source, TextFormat


def kev_entry(cve_id: str, date_added: str) -> dict:
    return {
        "cveID": cve_id,
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": date_added,
        "shortDescription": "JNDI features do not protect against attacker-controlled LDAP.",
        "requiredAction": "Apply updates per vendor�s instructions.",
        "knownRansomwareCampaignUse": "Known",
        "cwes": ["CWE-20", "CWE-917"],
    }


def test_kev_keeps_the_newest_entries() -> None:
    data = {
        "vulnerabilities": [
            kev_entry("CVE-2021-1", "2021-01-01"),
            kev_entry("CVE-2023-3", "2023-01-01"),
            kev_entry("CVE-2022-2", "2022-01-01"),
        ]
    }

    items = parse_kev(data, limit=2)

    assert [item.ref_id for item in items] == ["CVE-2023-3", "CVE-2022-2"]


def test_kev_item_text() -> None:
    [item] = parse_kev({"vulnerabilities": [kev_entry("CVE-2021-44228", "2021-12-10")]})

    assert item.source == Source.CVE
    assert item.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert "CWE-20, CWE-917" in item.text
    assert "Used in ransomware: Known" in item.text
    assert "vendor's instructions" in item.text  # broken apostrophe fixed


CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <Weaknesses>
    <Weakness ID="89" Name="SQL Injection" Status="Stable">
      <Description>The product builds an SQL command from input.</Description>
      <Extended_Description><xhtml:p>Without <xhtml:b>enough</xhtml:b> removal.</xhtml:p>
      </Extended_Description>
    </Weakness>
    <Weakness ID="1" Name="Old one" Status="Deprecated">
      <Description>Gone.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>"""


def test_cwe_reads_a_newer_schema_namespace() -> None:
    # MITRE moved the namespace from cwe-7 to cwe-8 in CWE 5.0 (2026-10-28);
    # a pinned namespace silently parsed zero weaknesses.
    [item] = parse_cwe(CWE_XML.replace("cwe-7", "cwe-8"))

    assert item.ref_id == "CWE-89"
    assert "enough" in item.text


def test_cwe_skips_deprecated_and_reads_xhtml_text() -> None:
    [item] = parse_cwe(CWE_XML)

    assert item.ref_id == "CWE-89"
    assert item.title == "SQL Injection"
    assert "Without enough removal." in item.text
    assert item.url == "https://cwe.mitre.org/data/definitions/89.html"


def technique(external_id: str, **extra: object) -> dict:
    return {
        "type": "attack-pattern",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may exploit a weakness.(Citation: NVD CVE-2016-6662)",
        "kill_chain_phases": [{"phase_name": "initial-access"}],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": external_id, "url": "https://x/T"}
        ],
        **extra,
    }


def test_attack_keeps_live_techniques_without_citations() -> None:
    bundle = {
        "objects": [
            technique("T1190"),
            technique("T0001", revoked=True),
            technique("T0002", x_mitre_deprecated=True),
            {"type": "malware", "name": "not a technique"},
        ]
    }

    [item] = parse_attack(bundle)

    assert item.ref_id == "T1190"
    assert "Tactics: initial-access" in item.text
    assert "Citation" not in item.text
    assert item.text_format == TextFormat.TEXT


def test_first_heading_drops_icons_and_attributes() -> None:
    markdown = '# A03:2021 – Injection    ![icon](assets/x.png){: style="height:80px"}\n\nbody'

    assert first_heading(markdown) == "A03:2021 – Injection"


def make_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_unzip_reads_the_one_xml_file() -> None:
    assert unzip_one_xml(make_zip({"cwec_v4.20.xml": b"<x/>"})) == "<x/>"


@pytest.mark.parametrize("files", [{"a.xml": b"<x/>", "b.xml": b"<y/>"}, {"run.sh": b"echo"}, {}])
def test_unzip_refuses_unexpected_contents(files: dict[str, bytes]) -> None:
    with pytest.raises(ValueError):
        unzip_one_xml(make_zip(files))


def test_unzip_refuses_a_zip_bomb(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(download, "MAX_UNZIPPED_BYTES", 1000)

    with pytest.raises(ValueError):
        unzip_one_xml(make_zip({"cwec.xml": b"<x>" + b"a" * 5000 + b"</x>"}))


def test_fetch_refuses_plain_http() -> None:
    with httpx.Client() as http, pytest.raises(ValueError):
        fetch(http, "http://cwe.mitre.org/data/xml/cwec_latest.xml.zip")


def test_fetch_does_not_follow_redirects() -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://evil.example/x"})

    with httpx.Client(transport=httpx.MockTransport(answer), follow_redirects=False) as http:
        with pytest.raises(httpx.HTTPStatusError):
            fetch(http, "https://www.cisa.gov/kev.json")


def test_github_sources_are_pinned_to_a_commit() -> None:
    for url in (download.ATTACK_URL, download.OWASP_TOP10_URL, download.OWASP_API_URL):
        assert "/master/" not in url
