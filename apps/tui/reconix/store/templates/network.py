"""Network template: hosts, ports and exposed services on a range or host."""

from ...models import ScopeManifest, Template
from ...models.parser import ParsedTarget
from .base import RunBundle, RunProfile, run_bundle

SCOPE_PROMPT = (
    "You scope an authorized network assessment of hosts and services. The default tool is "
    "nmap. For faster host/port discovery suggest masscan or rustscan; testssl.sh checks "
    "TLS; onesixtyone and enum4linux enumerate SNMP and SMB; whatweb fingerprints web ports. "
    "Never suggest destructive, exploitation or password tools (msfconsole, hydra). Stay on "
    "the approved hosts and ports."
)
SUGGEST_CATEGORIES = ["network", "recon"]
SPEC = Template("network", "Network", "Hosts, ports, and exposed services",
                target_hint="an IPv4 address or range, or a hostname", example="10.0.0.0/24")

ALLOWED_PORTS = [22, 80, 443, 8080, 8443]
TOOLS = ["nmap", "testssl.sh"]
# the scope tools each phase uses (the plan shows those still in the approved scope)
PHASE_TOOLS = {"discovery": ("nmap",), "scanning": ("nmap", "testssl.sh"),
               "validation": ("nmap",)}

def build_scope(parsed: ParsedTarget) -> ScopeManifest:
    return ScopeManifest(
        kind="network", target_url=parsed.target_url, assessment_type="Network",
        allowed_actions=["Host discovery", "port scan", "service detection"],
        allowed_methods=["TCP connect"],
        excluded_paths=[],       # network scope uses allowed_ports + the target range
        time_limit_minutes=0,   # no time limit by default; set one in the scope edit form
        tools=list(TOOLS),
        allowed_ports=list(ALLOWED_PORTS),
    )


def build_run(assessment) -> RunBundle:
    target = assessment.target
    scope = build_scope(ParsedTarget("network", target, target, "network range", "network",
                                     True))
    profile = RunProfile(
        target_kind="network range", tools=scope.tools,
        plan=(("discovery", "Host discovery"),
              ("scanning", "Port & service scan"),
              ("validation", "Validate exposures"),
              ("analysis", "Correlate & dedupe findings"),
              ("report", "Generate report")),
        methodology=("NIST SP 800-115", "PTES"),
    )
    return run_bundle(scope, profile, PHASE_TOOLS)
