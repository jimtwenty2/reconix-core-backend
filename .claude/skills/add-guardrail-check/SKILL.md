---
name: add-guardrail-check
description: Add or change a safety check, masking rule or audit event in services/ai/src/reconix_ai/harness. Use for the input, scope, command, risk and loop checks, secret masking, disclosure, and the audit log.
---

# Add a guardrail check

The harness is the part that makes "the AI suggests, the backend decides" true. It is **never cut** from scope.

## How the harness works

- `pipeline.py` runs the checks in this fixed order: **input → scope → command → risk → loop**. The first check that blocks stops the pipeline.
- Checks are pure functions. They **never read the database**; the API passes in everything they need (approved scope, recent runs, settings).
- The agent runs `check()` on every step it suggests, and the API runs it **again** right before any tool runs. Never add a path that skips the second run.
- Every decision writes exactly **one** audit line (JSON lines) with `assessment_id`, `session_id`, `role`, `actor` and an event type.

## Current rules (keep them true)

| Check | Blocks when |
|---|---|
| input | text > 4,000 chars, hidden control characters, prompt-injection phrases (also when hidden in base64 or hex, up to 2 levels deep) |
| scope | target not in an allowed IP range / exact or allowed domain / URL prefix / repo path; any `..` in a path; any excluded target; outside the time window; tool, action or method not allowed |
| command | tool is not one of nmap, nuclei, ZAP, semgrep, gitleaks; option not in that tool's allowlist (from `tool_specs.json`, copied from the Kali repo); any shell character; a blocked value: nmap port > 65535 or a broadcast/dos/target-adding script, nuclei `dos`/`fuzz` tag, a number outside its range (e.g. nuclei `-rate-limit` 1-150) |
| risk | level above the scope's max risk. Unknown tool/option = `HIGH`. Validating a finding is at least `MEDIUM` |
| loop | same command + target > 3 times in 10 minutes; > 20 actions in 1 minute; > 200 runs in one assessment |

Masking replaces passwords, tokens, API keys, private keys and session tokens with `[MASKED:<type>]` and returns a count. It runs **before** anything is saved, shown, sent to the AI or stored in Qdrant.

## Steps

1. Put the check in `harness/checks/<name>.py` as a function returning a result with `decision` (`ALLOW` / `BLOCKED`), `risk` and a short `reason` code.
2. Wire it into `pipeline.py` in the right position. Do not reorder existing checks.
3. Unit tests in `services/ai/tests/unit/harness/`: at least one allow, one block and one edge case per rule.
4. Property tests with Hypothesis for anything that parses targets or arguments. Always include: IPv6, punycode domains, URL-encoded input, path tricks (`..`, `//`, symlink-like names), and hidden output options such as `-oN /etc/x`.
5. If you add a new audit event type, tell the web/timeline owner; the timeline reads these lines.

## Done when

- All harness tests pass, and the full-flow test still passes with the real checks (not fakes).
