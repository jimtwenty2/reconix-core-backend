# Design Document: Reconix Operator AI Agent Skill (`reconix-operator`)

**Date**: 2026-11-16  
**Status**: Pending Approval  
**Owner**: Yann Vanneth  
**Target Environment**: `.agents/skills/reconix-operator/` (and `.claude/skills/reconix-operator/`)  

---

## 1. Intent and the "Why"

Reconix is an AI-assisted pentesting platform designed to operate on a tester's local machine against authorized targets. While Reconix has an interactive terminal UI (`apps/tui`) and web dashboard (`apps/web`), external security testers and automated red-team operators want their own autonomous AI agents (in Claude Code, Codex, Cursor, Antigravity, or custom agent runners) to drive Reconix.

The goal of this project is to create an exportable, self-contained AI Agent Skill (`reconix-operator`) that enables any AI coding/security agent to plan, execute, triage, and report on security assessments through Reconix while strictly adhering to safety rules S1–S10.

---

## 2. Goals, Non-Goals, and Anti-Goals

### Goals
- **Full Pentest Lifecycle**: Guide the AI agent through the required Reconix sequence:
  `Scope Definition` → `Assessment Planning` → `Action Execution & Approvals` → `Findings Triage` → `Report Generation`.
- **Hybrid Interface**: Use the Reconix Core MCP server (`/mcp`) for high-frequency scan queries and tool execution, and the Core REST API (`/api/v1`) for session lifecycle, approvals, and report exports.
- **Safety Enforcement**: Respect Reconix safety boundaries:
  - No action executes outside approved scope.
  - `LOW` risk runs automatically; `MEDIUM` and `HIGH` require explicit operator approval.
  - Compute single-use SHA-256 action hashes for approvals.
  - Secrets are masked at all stages.
- **Progressive Disclosure**: Keep token usage minimal by organizing the skill into a lightweight `SKILL.md` controller and specialized phase runbooks under `references/`.
- **Zero Hallucination with CLI Helper**: Provide a lightweight Python helper script (`scripts/rcx.py`) that manages session tokens, API calls, and SHA-256 action hashing so LLMs do not fail on complex JSON formatting or cryptographic hashes.

### Non-Goals
- Modifying the Core Backend API or altering safety check pipelines (`harness/pipeline.py`).
- Replacing the human operator's approval authority (the agent suggests and formats approvals; the human operator must authorize `MEDIUM`/`HIGH` actions).

### Anti-Goals
- **Bypassing the Harness**: The skill will never attempt to bypass the backend safety check (`check()`), forge approval tokens, or call the Kali Docker container directly without going through Reconix Core.
- **Dumping Raw Unmasked Secrets**: The skill and its helpers will never log or display unmasked passwords, API keys, or private evidence.

---

## 3. Constraints

- **Reconix Safety Rules (AGENTS.md S1–S10)**:
  - S1: Pipeline check order: `input → scope → command → risk → loop`.
  - S2: Dual-check verification (agent pre-check + backend pre-execution check).
  - S3: Strict target boundary enforcement.
  - S4: Risk tier gating (`LOW` auto, `MEDIUM`/`HIGH` wait for approval, > `max_risk` is 422 `BLOCKED`).
  - S5: 30-minute approval expiry, single use, SHA-256 action verification.
  - S8: Secret masking on all outputs.
  - S10: Localhost loopback binding (`127.0.0.1:8000`).
- **Runtime Dependencies**: Python >= 3.12 (standard for the repository), standard library `urllib` / `json` / `hashlib` to avoid external pip dependencies in `rcx.py`.

---

## 4. Approaches Considered

| Approach | Description | Trade-offs | Decision |
| :--- | :--- | :--- | :--- |
| **Approach 1: Modular Multi-Skill Suite** | 5 independent skills (`reconix-scope`, `reconix-plan`, etc.) | Granular, but high discovery overhead and lacks unified enforcement of the sequential safety flow. | Rejected |
| **Approach 2: Pure Markdown Runbooks** | Pure `SKILL.md` runbooks instructing raw curl calls and manual JSON math | Zero scripts, but error-prone; LLMs frequently hallucinate SHA-256 action hashes or curl escaping. High token usage. | Rejected |
| **Approach 3: Unified Operator Skill with Progressive References & CLI Helper** | Central `SKILL.md` + 5 phased references in `references/` + `scripts/rcx.py` helper | Clean progressive token loading, reliable token and hash management, zero syntax hallucinations, conforms to Antigravity skill standards. | **Selected (User Approved)** |

---

## 5. Detailed Design & Architecture

### Directory Structure

```text
.agents/skills/reconix-operator/
├── SKILL.md                 # Main workflow orchestrator (Phases 1 -> 5)
├── scripts/
│   └── rcx.py               # Lightweight helper: auth, REST/MCP bridge, approval hashing
└── references/
    ├── 01-scoping.md        # Rules for targets, CIDRs, exclusions, max_risk
    ├── 02-planning.md       # Tool capabilities (nmap, nuclei, zap, nikto, sqlmap) & phase strategies
    ├── 03-execution.md      # Action submission, LOW tracking vs MEDIUM/HIGH approval formatting
    ├── 04-findings.md       # Triage guide: severity ratings, evidence inspection, false positive flags
    └── 05-reporting.md      # Deliverable export formats (HTML, PDF, JSON) and executive summaries
```

### 5.1 Main Controller (`SKILL.md`)

The entry point defines the prompt triggers and guides the agent through the 5 phases:
- **Phase 1: Scoping**: Verifies targets, time windows, and creates an approved scope via `rcx.py scope-create`.
- **Phase 2: Planning**: Queries active Kali tools, drafts a phased plan, and registers it with the assessment.
- **Phase 3: Execution & Approvals**: Dispatches actions. If risk is `LOW`, runs immediately. If `MEDIUM`/`HIGH`, calculates the SHA-256 hash using `rcx.py hash-action`, presents the approval card to the operator, and submits the approval.
- **Phase 4: Findings Triage**: Collects discovered vulnerabilities, analyzes masked evidence snippets, and marks false positives.
- **Phase 5: Reporting**: Triggers report generation and downloads the sanitized HTML/PDF/JSON report.

### 5.2 Lightweight CLI Helper (`scripts/rcx.py`)

A single-file, zero-dependency Python 3 script using standard library modules (`urllib.request`, `json`, `hashlib`, `sys`, `os`, `argparse`).

**Supported Subcommands**:
1. `rcx.py status`: Pings `http://127.0.0.1:8000/health` and `/mcp` to ensure Reconix is online.
2. `rcx.py session`: Creates or caches a bearer session token (`POST /api/v1/sessions`) in `~/.reconix/session.json`.
3. `rcx.py scope create --target <cidr/ip/domain> --max-risk <LOW|MEDIUM|HIGH>`: Formats and posts the scope.
4. `rcx.py action plan --assessment-id <id>`: Submits planned action sequence.
5. `rcx.py action hash --action-json '<json>'`: Outputs the exact SHA-256 digest needed for approvals.
6. `rcx.py approve --action-id <id> --action-hash <hash> [--target-confirmation <target>]`: Approves gated actions.
7. `rcx.py findings list --assessment-id <id> [--severity <sev>]`: Lists findings.
8. `rcx.py report generate --assessment-id <id> --format <html|pdf|json>`: Requests deliverable compilation.

### 5.3 Reference Runbooks (`references/*.md`)

- `01-scoping.md`: Details how to structure CIDRs, exclude IPs, set `max_risk`, and prevent out-of-scope escapes.
- `02-planning.md`: Describes baseline risk of tools (`nmap` = LOW, `nuclei` = LOW/MEDIUM, `nikto` = MEDIUM, `sqlmap` = HIGH) and risk escalation triggers.
- `03-execution.md`: Explains approval timeouts (30 min), single-use tokens, and human gate presentation.
- `04-findings.md`: Guides validation using evidence vault pointers and CWE/CVSS mapping.
- `05-reporting.md`: Provides templates for executive summaries and compliance statements.

---

## 6. What's Left to the Builder (Implementation Calls)

- Mirroring the skill to `.claude/skills/reconix-operator/` to support both Claude Code and generic agent runners.
- Unit testing `rcx.py` functions (mocking HTTP calls) to ensure zero syntax or edge-case failures.
- Ensuring `rcx.py` properly honors environment variables `RECONIX_CORE_API_URL` (default `http://127.0.0.1:8000`) and `RECONIX_SESSION_TOKEN`.
