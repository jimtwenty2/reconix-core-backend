---
name: sync-kali-backend
description: Pull Reconix-Kali-MCP and reconcile Core against it — tool_specs.json, risk_ops.json, the command and risk allowlists, and a parser for each allowed tool. Use after a Kali-repo change, on merge days, and before a release.
---

# Sync with the Kali backend

The Kali container and its MCP server live in a **separate repo**, Reconix-Kali-MCP
(`github.com/14th-Generation-Advanced-Course/reconix-kali-backend`). Core talks to it only over MCP
and pulls its image by tag (`deploy/docker-compose.yml`, `ghcr.io/14th-generation-advanced-course/reconix-kali-mcp`).
Two files that repo owns are **copied into Core, never hand-edited**: `tool_specs.json` (the tool
catalog + baseline `risk`) and `risk_ops.json` (per-call risk escalations). Both are loaded at
runtime by `harness/catalog.py` and drive the command and risk checks, so Core can invoke **any**
tool the container offers. They drift silently — a stale copy means a new tool is unknown, a wrong
baseline mis-gates a scan, or a tool whose parser reads the wrong format keeps the run with **zero
findings** and no error. This skill reconciles them.

Core invokes tools by their catalog name. The 5 that have a structured-findings parser (NMAP,
NUCLEI, ZAP, SEMGREP, GITLEAKS) produce findings; the rest run and store raw masked output until a
parser exists. Adding a **parser** is `add-tool-parser` work; the catalog needs no code change.

## Steps

1. Fetch the Kali repo, read-only, into a temp dir:
   ```bash
   git clone --depth 1 https://github.com/14th-Generation-Advanced-Course/reconix-kali-backend /tmp/kali-sync
   ```
   (Or `git -C <existing checkout> fetch` if you already have a sibling clone.)
2. Copy both files over if they changed — **never hand-edit** (they load at runtime):
   ```bash
   diff /tmp/kali-sync/tool_specs.json services/ai/src/reconix_ai/tool_specs/tool_specs.json
   diff /tmp/kali-sync/risk_ops.json   services/ai/src/reconix_ai/tool_specs/risk_ops.json
   cp  /tmp/kali-sync/tool_specs.json /tmp/kali-sync/risk_ops.json \
       services/ai/src/reconix_ai/tool_specs/
   ```
3. Check what the diffs changed. Both feed `harness/catalog.py` with no code change needed:
   - a **new/removed tool** → it becomes invokable/blocked automatically;
   - a **baseline `risk`** change → re-gates every call of that tool (a tool dropping to `low`
     now auto-runs — note that in the commit);
   - a **`risk_ops.json`** escalation change → re-rates matching calls.
   Destructive tools and the free-shell set (run_command, proxychains, msfconsole, smbclient) are
   pinned to HIGH in `risk.py` regardless, so confirm the destructive flags still look right.
4. If Core calls a tool by a name that differs from the catalog's, add it to `ALIASES` in
   `harness/catalog.py` (today only `zap` → `zap_scan`). Nothing else in `command.py`/`risk.py`
   needs editing — there is no per-tool table any more.
5. **Parser check** — a tool only yields structured findings if it has a reader in `READERS`
   (`services/api/src/reconix_api/services/findings.py`) that reads the tool's real envelope
   `format`. The five with parsers today:

   | Tool | Envelope format | Core reader |
   |---|---|---|
   | NMAP | `xml` (needs `-oX -`) | `parsers/nmap.py` |
   | NUCLEI | `jsonl` (needs `-jsonl`) | `findings/json_mapping.py` |
   | SEMGREP | `json` (`--json`) | `findings/json_mapping.py` |
   | GITLEAKS | `json` array | `findings/json_mapping.py` |
   | ZAP | `sarif` (`zap_scan`, scoped to the target) | `parsers/sarif.py` |

   Any other catalog tool runs and stores raw masked output but produces no findings until someone
   runs the **`add-tool-parser`** skill for it. That is expected, not a bug.
6. Optional live check: call `tools_info` over MCP to list the running container's tool names and
   versions, and confirm the image matches the specs you just synced.

## Where it lives

No automated drift test exists yet, so do steps 2–5 by hand. `catalog.py` loads `tool_specs.json`
and `risk_ops.json` at runtime and caches them, so a copy takes effect on the next process start.

## Do not

- Hand-edit `tool_specs.json` or `risk_ops.json` — copy them whole from the Kali repo.
- Re-introduce a per-tool option allowlist — gating is baseline + risk_ops + approval by design.
- Weaken the free-shell / destructive → HIGH rule, or exempt a tool from the control/shell-character
  block, without the lead (`AGENTS.md` §10): these are safety-rule (S6) changes.
- Parse tool output inside the Kali container — the container returns raw output, Core makes findings.
