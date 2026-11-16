# Phase 2: Assessment Planning Runbook

Reconix organizes penetration tests into disciplined phases. Tools are pre-approved in the Kali catalog (`tool_specs.json`).

## 1. Tool Catalog & Baseline Risk

Only tools registered in the Kali MCP server catalog may be proposed:

| Tool | Purpose | Baseline Risk | Escalation Trigger |
| :--- | :--- | :--- | :--- |
| `nmap` | Host discovery & port scanning | `LOW` | Heavy timing templates (`-T4`/`-T5`), aggressive NSE scripts (`--script=vuln`) escalate to `MEDIUM` |
| `nuclei` | Vulnerability scanning | `LOW` | Critical/High tags, fuzzing or write payloads escalate to `MEDIUM`/`HIGH` |
| `nikto` | Web server configuration scanning | `MEDIUM` | Intrusive plug-ins |
| `sqlmap` | Automated SQL injection testing | `HIGH` | Gated at `HIGH`, requires target confirmation |
| `zap` | Dynamic Application Security Testing | `MEDIUM` | Active scanning mode |

---

## 2. Attack Surface Strategy (The 3 Phases)

Structure the assessment plan into three sequential phases:

### Phase 1: Host & Port Discovery
- **Action**: Run `nmap` against target CIDR or IPs to discover open ports and services.
- **Example command**: `["nmap", "-sS", "-Pn", "--top-ports", "1000", "<target>"]`
- **Risk**: `LOW` (runs automatically).

### Phase 2: Service Fingerprinting & Basic Enumeration
- **Action**: Run targeted banner grabbing and basic template scans on discovered web ports (80, 443, 8080).
- **Example command**: `["nuclei", "-target", "https://<target>", "-tags", "cve,tech"]`
- **Risk**: `LOW` to `MEDIUM`.

### Phase 3: Targeted Vulnerability Verification
- **Action**: Probe specific identified endpoints with dedicated tools based on findings in Phase 2.
- **Risk**: `MEDIUM` to `HIGH` (operator approval mandatory).

---

## 3. Registering the Plan

Once the phases and candidate actions are drafted, submit them via the Core API or Core MCP tool `plan_assessment`.
