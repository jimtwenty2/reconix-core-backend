---
name: run-leak-test
description: Prove no secret leaks into the database, logs, audit log, AI messages or Qdrant after a full run. Use after changing masking, parsers, evidence, reports, AI provider handling, or before a release.
---

# Run the leak test

Secret masking is **never cut**. The test passes only if a planted secret appears in **none** of the places below.

## Steps

1. Use the lab test repo that contains the known fake secret, plus a fake AI provider API key (e.g. `sk-test-LEAKCANARY-0000`). Treat these strings as canaries.
2. Run the full flow with gitleaks and semgrep on the test repo, and save an AI provider with the canary key.
3. Search every sink for the canary values (and their base64 forms):
   - PostgreSQL: dump all text/JSON columns (`pg_dump --data-only` then grep)
   - API and AI Service logs, and the audit JSONL file
   - Messages sent to the model (log them through the fake provider in test mode)
   - Qdrant payloads (scroll the collections and grep)
   - Report files (PDF text, DOCX text, JSON)
   - API responses: provider keys show only the last 4 characters
4. Expected: zero hits, and masked values appear as `[MASKED:<type>]` with a non-zero mask count on the tool run.
5. Check disclosure: with a `disclosure` approval, the real value is shown once; a second read is refused.

## Where it lives

Automate it as `services/api/tests/security/test_no_secret_leaks.py` so CI runs it on every PR.
