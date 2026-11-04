"""Download the public knowledge once and save it as JSON Lines.

Run by a person, with internet, before the first ingest:
    uv run --package reconix-ai python -m reconix_ai.knowledge.download

Sources (see data/knowledge-sample/SOURCES.md for their licences):
- CVE: the 1,000 newest entries of CISA's Known Exploited Vulnerabilities list
- CWE: every weakness in MITRE's CWE list that is not deprecated
- OWASP Top 10 2021 and OWASP API Security Top 10 2023: one page per risk
- ATT&CK: every Enterprise technique that is not revoked or deprecated
"""

import io
import json
import re
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import httpx

from reconix_ai.knowledge.items import KnowledgeItem, Source, TextFormat, write_items
from reconix_ai.knowledge.paths import FULL_DATA_DIR

CVE_LIMIT = 1000
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
# The GitHub sources are pinned to one commit, so a later change upstream cannot
# slip new text into the agent's knowledge. Move a pin on purpose, by PR.
ATTACK_COMMIT = "50be388e93819a5d20e71cbaaeccfda157abc846"
OWASP_TOP10_COMMIT = "3a31f35346c3f4e90f350395124382fa53af2afe"
OWASP_API_COMMIT = "33cea37b2ffde3e2e62f6b5d79a029a22a846633"
ATTACK_URL = (
    f"https://raw.githubusercontent.com/mitre/cti/{ATTACK_COMMIT}"
    "/enterprise-attack/enterprise-attack.json"
)
OWASP_TOP10_URL = (
    f"https://raw.githubusercontent.com/OWASP/Top10/{OWASP_TOP10_COMMIT}/2021/docs/en/{{name}}.md"
)
# The page a person reads, shown with each hit.
OWASP_TOP10_PAGE_URL = "https://top10.owasp.org/{name}/"
OWASP_TOP10_PAGES = [
    ("A01:2021", "A01_2021-Broken_Access_Control"),
    ("A02:2021", "A02_2021-Cryptographic_Failures"),
    ("A03:2021", "A03_2021-Injection"),
    ("A04:2021", "A04_2021-Insecure_Design"),
    ("A05:2021", "A05_2021-Security_Misconfiguration"),
    ("A06:2021", "A06_2021-Vulnerable_and_Outdated_Components"),
    ("A07:2021", "A07_2021-Identification_and_Authentication_Failures"),
    ("A08:2021", "A08_2021-Software_and_Data_Integrity_Failures"),
    ("A09:2021", "A09_2021-Security_Logging_and_Monitoring_Failures"),
    ("A10:2021", "A10_2021-Server-Side_Request_Forgery_(SSRF)"),
]
OWASP_API_URL = (
    f"https://raw.githubusercontent.com/OWASP/API-Security/{OWASP_API_COMMIT}"
    "/editions/2023/en/{name}.md"
)
OWASP_API_PAGE_URL = "https://api-security.owasp.org/editions/2023/en/{name}/"
OWASP_API_PAGES = [
    ("API1:2023", "0xa1-broken-object-level-authorization"),
    ("API2:2023", "0xa2-broken-authentication"),
    ("API3:2023", "0xa3-broken-object-property-level-authorization"),
    ("API4:2023", "0xa4-unrestricted-resource-consumption"),
    ("API5:2023", "0xa5-broken-function-level-authorization"),
    ("API6:2023", "0xa6-unrestricted-access-to-sensitive-business-flows"),
    ("API7:2023", "0xa7-server-side-request-forgery"),
    ("API8:2023", "0xa8-security-misconfiguration"),
    ("API9:2023", "0xa9-improper-inventory-management"),
    ("API10:2023", "0xaa-unsafe-consumption-of-apis"),
]
CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
# The CWE XML is about 20 MB unzipped; refuse anything far bigger (a zip bomb).
MAX_UNZIPPED_BYTES = 200 * 1024 * 1024


# ---------------------------------------------------------------------------
# Parsing: raw source -> items. No network, so these are unit tested.
# ---------------------------------------------------------------------------


def parse_kev(data: dict, limit: int = CVE_LIMIT) -> list[KnowledgeItem]:
    """The newest `limit` known exploited CVEs."""
    entries = sorted(data["vulnerabilities"], key=lambda v: v["dateAdded"], reverse=True)
    return [kev_item(entry) for entry in entries[:limit]]


def kev_item(entry: dict) -> KnowledgeItem:
    cve_id = entry["cveID"]
    cwes = ", ".join(entry.get("cwes") or []) or "not given"
    text = (
        f"{cve_id}: {entry['vulnerabilityName']}. {entry['shortDescription']}\n"
        f"Vendor: {entry['vendorProject']}. Product: {entry['product']}.\n"
        f"Weaknesses: {cwes}.\n"
        f"Known to be exploited in the wild (CISA KEV, added {entry['dateAdded']}). "
        f"Used in ransomware: {entry.get('knownRansomwareCampaignUse', 'Unknown')}.\n"
        f"Required action: {entry['requiredAction']}"
    )
    return KnowledgeItem(
        source=Source.CVE,
        ref_id=cve_id,
        title=entry["vulnerabilityName"],
        # CISA's file has some apostrophes saved as broken characters.
        text=text.replace("�", "'"),
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


def parse_cwe(xml_text: str) -> list[KnowledgeItem]:
    # MITRE's own file over HTTPS. ElementTree never loads external entities, and
    # expat (2.4+) stops "billion laughs" entity expansion.
    root = ElementTree.fromstring(xml_text)  # noqa: S314
    items = []
    for weakness in root.iterfind("cwe:Weaknesses/cwe:Weakness", CWE_NS):
        if weakness.get("Status") == "Deprecated":
            continue
        items.append(cwe_item(weakness))
    return items


def cwe_item(weakness: ElementTree.Element) -> KnowledgeItem:
    cwe_id = f"CWE-{weakness.get('ID')}"
    name = weakness.get("Name", "")
    parts = [f"{cwe_id}: {name}.", element_text(weakness.find("cwe:Description", CWE_NS))]
    extended = element_text(weakness.find("cwe:Extended_Description", CWE_NS))
    if extended:
        parts.append(extended)
    return KnowledgeItem(
        source=Source.CWE,
        ref_id=cwe_id,
        title=name,
        text="\n".join(part for part in parts if part),
        url=f"https://cwe.mitre.org/data/definitions/{weakness.get('ID')}.html",
    )


def element_text(element: ElementTree.Element | None) -> str:
    """All the text inside an element, including its XHTML children, on one line."""
    if element is None:
        return ""
    return " ".join(" ".join(element.itertext()).split())


def parse_attack(bundle: dict) -> list[KnowledgeItem]:
    items = []
    for entry in bundle["objects"]:
        if entry.get("type") != "attack-pattern":
            continue
        if entry.get("revoked") or entry.get("x_mitre_deprecated"):
            continue
        item = attack_item(entry)
        if item is not None:
            items.append(item)
    return items


def attack_item(entry: dict) -> KnowledgeItem | None:
    reference = next(
        (
            ref
            for ref in entry.get("external_references", [])
            if ref["source_name"] == "mitre-attack"
        ),
        None,
    )
    if reference is None:
        return None
    technique_id = reference["external_id"]
    tactics = ", ".join(phase["phase_name"] for phase in entry.get("kill_chain_phases", []))
    description = re.sub(r"\(Citation: [^)]*\)", "", entry.get("description", ""))
    text = f"{technique_id}: {entry['name']}. Tactics: {tactics or 'not given'}.\n{description}"
    return KnowledgeItem(
        source=Source.ATTACK,
        ref_id=technique_id,
        title=entry["name"],
        text=text.strip(),
        url=reference.get("url", ""),
    )


def owasp_item(source: Source, ref_id: str, markdown: str, url: str) -> KnowledgeItem:
    return KnowledgeItem(
        source=source,
        ref_id=ref_id,
        title=first_heading(markdown) or ref_id,
        text=markdown.strip(),
        url=url,
        text_format=TextFormat.MARKDOWN,
    )


def first_heading(markdown: str) -> str:
    match = re.search(r"^#\s+(.+)$", markdown, re.MULTILINE)
    if not match:
        return ""
    heading = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", match.group(1))  # drop icon images
    heading = re.sub(r"\{:[^}]*\}", "", heading)  # and their {: style=...} attributes
    return " ".join(heading.split())


# ---------------------------------------------------------------------------
# Downloading
# ---------------------------------------------------------------------------


def download_all(out_dir: Path = FULL_DATA_DIR) -> dict[Source, int]:
    """Download every source, then save them all, and return how many items each has.

    Nothing is written until every source has downloaded, so a failure halfway
    never leaves a partial set for the ingest to pick up.
    """
    # No redirects: every address is HTTPS and final, so a redirect is a surprise.
    with httpx.Client(timeout=120, follow_redirects=False) as http:
        downloaded = {
            Source.CVE: parse_kev(fetch(http, KEV_URL).json()),
            Source.CWE: parse_cwe(unzip_one_xml(fetch(http, CWE_URL).content)),
            Source.ATTACK: parse_attack(fetch(http, ATTACK_URL).json()),
            Source.OWASP_TOP10: owasp_pages(
                http, Source.OWASP_TOP10, OWASP_TOP10_URL, OWASP_TOP10_PAGE_URL, OWASP_TOP10_PAGES
            ),
            Source.OWASP_API_TOP10: owasp_pages(
                http, Source.OWASP_API_TOP10, OWASP_API_URL, OWASP_API_PAGE_URL, OWASP_API_PAGES
            ),
        }
    for source, items in downloaded.items():
        write_items(out_dir / f"{source.lower()}.jsonl", items)
        print(f"{source}: {len(items)} items")
    return {source: len(items) for source, items in downloaded.items()}


def fetch(http: httpx.Client, url: str) -> httpx.Response:
    if not url.startswith("https://"):
        raise ValueError(f"Only HTTPS sources are allowed: {url}")
    return http.get(url).raise_for_status()


def unzip_one_xml(content: bytes) -> str:
    """The single XML file in the zip, refusing anything that unpacks too big."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        if len(members) != 1 or not members[0].filename.endswith(".xml"):
            raise ValueError("The CWE zip should hold exactly one .xml file.")
        with archive.open(members[0]) as file:
            # Read one byte past the limit: the size in the zip header can lie.
            data = file.read(MAX_UNZIPPED_BYTES + 1)
    if len(data) > MAX_UNZIPPED_BYTES:
        raise ValueError("The CWE file is far bigger than expected.")
    return data.decode("utf-8")


def owasp_pages(
    http: httpx.Client,
    source: Source,
    url_template: str,
    page_url_template: str,
    pages: list[tuple[str, str]],
) -> list[KnowledgeItem]:
    items = []
    for ref_id, name in pages:
        markdown = fetch(http, url_template.format(name=name)).text
        items.append(owasp_item(source, ref_id, markdown, page_url_template.format(name=name)))
    return items


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else FULL_DATA_DIR
    print(json.dumps(download_all(out), indent=2))
