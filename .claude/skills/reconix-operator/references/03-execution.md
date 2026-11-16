# Phase 3: Action Execution & Approval Runbook

Reconix strictly separates suggestion from execution. **The AI suggests, the backend decides.**

## 1. Action Execution Lifecycle

Every suggested action passes through the dual safety check:
1. Agent pre-check.
2. Core API pre-execution check (`services/api/src/reconix_api/services/actions.py`).

```text
Action Propose ──> Check Pipeline ──┬─ LOW ────> Run immediately in Kali
                                    ├─ MEDIUM ─> Human Gate (Approve hash)
                                    └─ HIGH ───> Human Gate (Approve hash + Type target)
```

---

## 2. Handling the Human Approval Gate

When an action is rated `MEDIUM` or `HIGH`:
1. The Core API generates a pending approval record and computes the canonical SHA-256 action hash.
2. **Approvals expire in 30 minutes** and are strictly single-use.
3. Present the approval request clearly to the human operator:

```text
============================================================
🚨 APPROVAL REQUIRED: Action [act_91a0b]
Tool:        nikto
Target:      https://192.168.1.100:8443
Risk Level:  MEDIUM
Reason:      Web server vulnerability probing
Command:     nikto -h https://192.168.1.100:8443 -ssl
Action Hash: 7e89b...41a
============================================================
Reply 'approve' to authorize, or 'reject' to skip.
```

---

## 3. Submitting Approval with `rcx.py`

Calculate the action hash if not provided, and submit approval:

```bash
# 1. Compute hash
python3 scripts/rcx.py action-hash --action-json '{"tool": "nikto", "params": {"target": "192.168.1.100"}}'

# 2. Submit approval
python3 scripts/rcx.py approve \
  --action-id "act_91a0b" \
  --action-hash "7e89b...41a" \
  --confirm-target "192.168.1.100"  # Required if risk is HIGH
```
