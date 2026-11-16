# Reconix Operator Skill (`reconix-operator`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the exportable `reconix-operator` AI agent skill package containing a zero-dependency Python helper script (`scripts/rcx.py`), 5 progressive reference runbooks, and a central `SKILL.md` controller to allow external AI agents to drive the Reconix pentest platform.

**Architecture:** A lightweight CLI helper (`scripts/rcx.py`) encapsulates all REST and MCP interactions with Reconix Core (loopback `127.0.0.1:8000`), handles bearer token caching, and computes single-use SHA-256 action hashes. A main `SKILL.md` orchestrates the 5 pentest phases, loading detailed markdown runbooks from `references/` on demand to conserve token context.

**Tech Stack:** Python 3.12 (standard library `urllib.request`, `json`, `hashlib`, `argparse`, `sys`, `os`), Markdown (YAML frontmatter for Agentic/Claude/Antigravity skill standards).

**Spec:** [`docs/superpowers/specs/2026-11-16-reconix-operator-skill-design.md`](file:///home/yannvanneth/orca/workspaces/reconix-core-backend/Develop/docs/superpowers/specs/2026-11-16-reconix-operator-skill-design.md)

## Global Constraints

- **Python Version**: Python >= 3.12.
- **Dependencies in `rcx.py`**: Zero external pip dependencies; use standard library only (`urllib.request`, `json`, `hashlib`, etc.).
- **Safety Enforcement**: Adhere strictly to Reconix safety rules S1–S10 (scope bounding, `LOW` auto-run, `MEDIUM`/`HIGH` approval gating with SHA-256 hash, secret masking).
- **Default Core API URL**: `http://127.0.0.1:8000`, overrideable via `RECONIX_CORE_API_URL`.
- **Mirroring**: Skill must exist identically in both `.agents/skills/reconix-operator/` and `.claude/skills/reconix-operator/`.

## Review Focus

1. **Unreachable Core API**: `rcx.py` commands handle connection errors gracefully, returning exit code 1 with clean instructions (`Reconix API is offline at http://127.0.0.1:8000. Start it with docker compose up -d`).
2. **Expired or Invalid Session Token**: `rcx.py` detects HTTP 401, clears invalid cached credentials, and re-authenticates automatically.
3. **Mismatched SHA-256 Action Hash**: Action hashing strips extraneous whitespace and sorts JSON keys so hash computation matches the backend's SHA-256 verification exactly.
4. **Out-of-Scope Target Refusal**: Scoping input prevents invalid IP/CIDR syntax before sending to the backend.
5. **Secret Masking Leakage**: Output logs and finding evidence never strip or display raw secrets.

---

### Task 1: `rcx.py` Helper Core (Config, Session Auth, Status)

**Files:**
- Create: `.agents/skills/reconix-operator/scripts/rcx.py`
- Test: `services/api/tests/unit/test_rcx_helper.py`

**Interfaces:**
- Produces:
  - `get_base_url() -> str`
  - `get_session_token(force_refresh: bool = False) -> str`
  - `check_status() -> dict[str, Any]`
  - `CLI commands: rcx.py status`, `rcx.py session`

- [ ] **Step 1: Write the failing unit test for status and session auth**

```python
# services/api/tests/unit/test_rcx_helper.py
import importlib.util
from pathlib import Path
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location(
    "rcx", Path(".agents/skills/reconix-operator/scripts/rcx.py").resolve()
)
rcx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rcx)


def test_status_returns_health_dict():
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status": "ok", "version": "0.1.0"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response
        res = rcx.check_status()
        assert res["status"] == "ok"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --package reconix-api pytest services/api/tests/unit/test_rcx_helper.py -v`
Expected: FAIL with FileNotFoundError or ModuleNotFoundError.

- [ ] **Step 3: Implement `rcx.py` core CLI and auth methods**

Implement `get_base_url()`, `request(path, method, data, token)`, `check_status()`, and `get_session_token()` caching token to `~/.reconix/session.json`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --package reconix-api pytest services/api/tests/unit/test_rcx_helper.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .agents/skills/reconix-operator/scripts/rcx.py services/api/tests/unit/test_rcx_helper.py
git commit -m "feat(skills): implement rcx.py core auth and status helper"
```

---

### Task 2: `rcx.py` Scope, Action, and Approval Hash Management

**Files:**
- Modify: `.agents/skills/reconix-operator/scripts/rcx.py`
- Modify: `services/api/tests/unit/test_rcx_helper.py`

**Interfaces:**
- Consumes: `request(path, method, data, token)` from Task 1
- Produces:
  - `create_scope(target: str, max_risk: str, exclusions: list[str]) -> dict`
  - `compute_action_hash(action_dict: dict) -> str`
  - `submit_approval(action_id: str, action_hash: str, target_confirmation: str | None) -> dict`

- [ ] **Step 1: Write the failing unit tests for hashing and approvals**

```python
# Add to services/api/tests/unit/test_rcx_helper.py
def test_compute_action_hash_deterministic():
    action = {
        "tool": "nmap",
        "params": {"target": "10.0.0.1", "ports": "80,443"},
        "risk": "MEDIUM",
    }
    h1 = rcx.compute_action_hash(action)
    # Permute keys to verify sorted canonicalization
    action_permuted = {
        "risk": "MEDIUM",
        "tool": "nmap",
        "params": {"ports": "80,443", "target": "10.0.0.1"},
    }
    h2 = rcx.compute_action_hash(action_permuted)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex string
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --package reconix-api pytest services/api/tests/unit/test_rcx_helper.py -k test_compute_action_hash -v`
Expected: FAIL with AttributeError: module 'rcx' has no attribute 'compute_action_hash'.

- [ ] **Step 3: Implement scope and action approval methods in `rcx.py`**

Implement `compute_action_hash(action)` canonicalizing JSON via `json.dumps(action, sort_keys=True, separators=(',', ':'))`, `create_scope()`, and `submit_approval()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --package reconix-api pytest services/api/tests/unit/test_rcx_helper.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .agents/skills/reconix-operator/scripts/rcx.py services/api/tests/unit/test_rcx_helper.py
git commit -m "feat(skills): implement scope creation and SHA-256 action hashing in rcx.py"
```

---

### Task 3: `rcx.py` Findings & Report Export Commands

**Files:**
- Modify: `.agents/skills/reconix-operator/scripts/rcx.py`
- Modify: `services/api/tests/unit/test_rcx_helper.py`

**Interfaces:**
- Consumes: `request(path, method, data, token)` from Task 1
- Produces:
  - `list_findings(assessment_id: str, severity: str | None) -> list[dict]`
  - `generate_report(assessment_id: str, format: str) -> dict`
  - `download_report(report_id: str, output_path: str) -> str`

- [ ] **Step 1: Write the failing unit tests for findings and report download**

```python
# Add to services/api/tests/unit/test_rcx_helper.py
def test_list_findings_filters_by_severity():
    with patch.object(rcx, "request") as mock_req:
        mock_req.return_value = [{"id": "f-1", "severity": "HIGH", "title": "SQLi"}]
        res = rcx.list_findings("test-assess-1", severity="HIGH")
        assert len(res) == 1
        assert res[0]["title"] == "SQLi"
        mock_req.assert_called_once()
        assert "severity=HIGH" in mock_req.call_args[0][0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --package reconix-api pytest services/api/tests/unit/test_rcx_helper.py -k test_list_findings -v`
Expected: FAIL with AttributeError: module 'rcx' has no attribute 'list_findings'.

- [ ] **Step 3: Implement findings query and report compilation in `rcx.py`**

Implement `list_findings()`, `generate_report()`, and `download_report()` with CLI argument parsing subcommands (`findings`, `report`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --package reconix-api pytest services/api/tests/unit/test_rcx_helper.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .agents/skills/reconix-operator/scripts/rcx.py services/api/tests/unit/test_rcx_helper.py
git commit -m "feat(skills): implement findings and reporting commands in rcx.py"
```

---

### Task 4: Progressive Reference Runbooks (01–05)

**Files:**
- Create: `.agents/skills/reconix-operator/references/01-scoping.md`
- Create: `.agents/skills/reconix-operator/references/02-planning.md`
- Create: `.agents/skills/reconix-operator/references/03-execution.md`
- Create: `.agents/skills/reconix-operator/references/04-findings.md`
- Create: `.agents/skills/reconix-operator/references/05-reporting.md`

**Interfaces:**
- Consumes: `rcx.py` CLI command signatures from Tasks 1–3
- Produces: 5 structured runbooks adhering to progressive disclosure guidelines.

- [ ] **Step 1: Create `01-scoping.md`**
  Document target formatting (IPs, CIDRs, domains), exclusions, time windows, and max risk levels (`LOW`, `MEDIUM`, `HIGH`). Include `rcx.py scope` examples.

- [ ] **Step 2: Create `02-planning.md`**
  Document Kali catalog tool specs (`nmap`, `nuclei`, `nikto`, `sqlmap`, `zap`), baseline risk, and staged pentest phase design.

- [ ] **Step 3: Create `03-execution.md`**
  Document execution loop, `LOW` auto-run, `MEDIUM`/`HIGH` human gate presentation, 30-minute approval timeout, and SHA-256 verification.

- [ ] **Step 4: Create `04-findings.md`**
  Document finding triage (CWE, CVSS, severity), evidence analysis, and marking false positives.

- [ ] **Step 5: Create `05-reporting.md`**
  Document executive summary generation, report format export (`HTML`, `PDF`, `JSON`), and secret sanitization check.

- [ ] **Step 6: Commit**

```bash
git add .agents/skills/reconix-operator/references/
git commit -m "docs(skills): add progressive reference runbooks 01 through 05"
```

---

### Task 5: Main `SKILL.md` Controller & Multi-Agent Mirroring

**Files:**
- Create: `.agents/skills/reconix-operator/SKILL.md`
- Copy/Mirror: `.claude/skills/reconix-operator/` (full directory mirror)

**Interfaces:**
- Consumes: Tasks 1–4
- Produces: Main skill definition with YAML frontmatter activating on pentest operator queries.

- [ ] **Step 1: Create `.agents/skills/reconix-operator/SKILL.md`**
  Write frontmatter with `name: reconix-operator` and comprehensive description. Detail the 5 phases with links to relative `./references/0X-*.md` files and `./scripts/rcx.py` usage.

- [ ] **Step 2: Mirror skill package into `.claude/skills/reconix-operator/`**
  Ensure Claude Code users and generic agent runners have identical access.

- [ ] **Step 3: Verify linting and file validity**
  Verify markdown links and run `uv run ruff check .agents/skills/reconix-operator/scripts/`.

- [ ] **Step 4: Commit**

```bash
git add .agents/skills/reconix-operator/ .claude/skills/reconix-operator/
git commit -m "feat(skills): add main SKILL.md and mirror to .claude directory"
```

---

### Task 6: End-to-End Verification

**Files:**
- Test: `services/api/tests/unit/test_rcx_helper.py`

- [ ] **Step 1: Run full test suite for `rcx_helper.py`**

Run: `uv run --package reconix-api pytest services/api/tests/unit/test_rcx_helper.py -v`
Expected: 100% PASS with all mocked network conditions tested.

- [ ] **Step 2: Verify `rcx.py --help` CLI execution**

Run: `python3 .agents/skills/reconix-operator/scripts/rcx.py --help`
Expected: Exit code 0, displaying all subcommands.

- [ ] **Step 3: Run project linters**

Run: `uv run ruff check .agents/skills/reconix-operator/scripts/`
Expected: 0 errors.

- [ ] **Step 4: Commit and finalize**

```bash
git commit --allow-empty -m "chore(skills): complete end-to-end verification of reconix-operator skill"
```
