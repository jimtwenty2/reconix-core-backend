---
name: add-tool-parser
description: Parse raw output from a Kali tool (nmap, nuclei, ZAP, semgrep, gitleaks) into Reconix findings and evidence in services/api parsers/ and findings/. Use when adding or fixing a parser, the finding shape, or dedupe.
---

# Add a tool parser

The Kali MCP container returns **raw output only** (status, exit code, stdout/stderr, the tool's result file, duration, truncated flag). All parsing and finding logic lives in the backend.

| Tool | Raw format |
|---|---|
| nmap | XML |
| nuclei | JSONL |
| ZAP | JSON report |
| semgrep | JSON |
| gitleaks | JSON |

## Steps

1. Save a real (masked) sample output in `services/api/tests/fixtures/<tool>/`. Get it from a run against the lab, never from a real target.
2. Write `services/api/src/reconix_api/parsers/<tool>.py`: one function `parse(raw) -> list[RawResult]`. It only reads; no database, no HTTP.
3. Normalize in `findings/` into the one finding shape:
   - title, target, description, location
   - severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` or `NONE`. If the tool has no clear severity, use **`UNKNOWN`**. Never guess.
   - CVSS score, CWE, OWASP and CVE ids when present
4. **Dedupe**: build a stable `dedupe_key` (e.g. target + location + rule/CVE). When two tools find the same thing, keep one finding that lists both sources.
5. **Evidence**: one record per piece of proof — the masked content, where it was found, and the `tool_run` that found it. Run masking on evidence before saving.
6. Count the requests each run sent and store it on the tool run.
7. Tests in `services/api/tests/unit/parsers/` using the fixtures: expected findings, severity mapping, dedupe, and a truncated/empty/malformed output case that fails cleanly.

## Do not

- Do not parse inside the Kali container.
- Do not add tools beyond the 5. Allowed options come only from `tool_specs.json`.
- Do not keep a raw secret in any field. gitleaks output is all secrets: mask it before it reaches a finding.
