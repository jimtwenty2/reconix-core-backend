"""Network template: hosts, ports and exposed services on a range or host."""

from ...models import ScopeManifest, Template
from ...models.parser import ParsedTarget
from .base import RunBundle, RunProfile, run_bundle

SCOPE_PROMPT = (
    "You scope an authorized network assessment of hosts and services. It covers these "
    "techniques: host discovery, port scanning, service, version and OS detection and the "
    "firewall view (nmap; masscan or rustscan for a fast sweep), CVE matching (nuclei, "
    "searchsploit), misconfiguration checks (nuclei; enum4linux enumerates SMB on 139/445, "
    "onesixtyone checks SNMP on 161) and SSL/TLS (testssl). The default tools are nmap, "
    "Nuclei, testssl, enum4linux and onesixtyone (all read-only enumeration). Run "
    "enum4linux only when SMB (139/445) is open and onesixtyone only when SNMP (161) is "
    "open. Network segmentation is checked by hand. Never suggest destructive, exploitation "
    "or password tools (msfconsole, hydra). Stay on the approved hosts and ports."
)
SUGGEST_CATEGORIES = ["network", "recon"]
SPEC = Template(
    "network",
    "Network",
    "Hosts, ports, and exposed services",
    target_hint="an IPv4 address or range, or a hostname",
    example="10.0.0.0/24",
)

# Common service ports: remote access, mail, DNS, file sharing, databases and web.
ALLOWED_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    137,
    139,
    143,
    161,
    389,
    443,
    445,
    993,
    995,
    1433,
    1521,
    2049,
    3000,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    9200,
    27017,
]
TOOLS = ["nmap", "Nuclei", "testssl.sh", "enum4linux", "onesixtyone"]
# the scope tools each phase uses (the plan shows those still in the approved scope)
PHASE_TOOLS = {
    "discovery": ("nmap",),
    "scanning": ("nmap", "Nuclei", "testssl.sh", "enum4linux", "onesixtyone"),
    "validation": ("nmap", "Nuclei"),
}


def build_scope(parsed: ParsedTarget) -> ScopeManifest:
    return ScopeManifest(
        kind="network",
        target_url=parsed.target_url,
        assessment_type="Network",
        allowed_actions=["Host discovery", "port scan", "service detection"],
        allowed_methods=["TCP connect"],
        excluded_paths=[],  # network scope uses allowed_ports + the target range
        time_limit_minutes=0,  # no time limit by default; set one in the scope edit form
        tools=list(TOOLS),
        allowed_ports=list(ALLOWED_PORTS),
    )


def build_run(assessment) -> RunBundle:
    target = assessment.target
    scope = build_scope(ParsedTarget("network", target, target, "network range", "network", True))
    profile = RunProfile(
        target_kind="network range",
        tools=scope.tools,
        plan=(
            ("discovery", "Host discovery"),
            ("scanning", "Port & service scan"),
            ("validation", "Validate exposures"),
            ("analysis", "Correlate & dedupe findings"),
            ("report", "Generate report"),
        ),
        methodology=("Guided by NIST SP 800-115", "PTES"),
    )
    return run_bundle(scope, profile, PHASE_TOOLS)
