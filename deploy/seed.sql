-- Sample data for Reconix-Core (ERD V3 names, UPPERCASE enum values).
--
-- One web test of a Juice Shop demo, from scope to findings:
--   a session with its chat, an ACTIVE assessment with an APPROVED scope, one agent run,
--   three actions (NMAP ran at LOW, NUCLEI ran after an approval, ZAP waits for one),
--   two tool runs, four findings with evidence, and one PoC validation.
--
-- Fake data only: reserved domains (*.example), documentation IPs (192.0.2.0/24), no secrets.
-- Ids are fixed so the sample JSON in apps/sample-data/ stays the same between builds.
-- No report row: make one with POST /assessments/{assessment_id}/reports.
-- The ZAP approval stays PENDING, but its 30 minutes ended on 2 Nov 2026: approving it now
-- answers that it expired. Send the action again for a fresh one.
--
-- Load it into the stack's empty database (the api service migrates it when it starts):
--   docker compose -f deploy/docker-compose.yml --env-file .env exec -T postgres \
--     psql -U reconix -d reconix -v ON_ERROR_STOP=1 < deploy/seed.sql
-- Then rebuild the sample files: uv run python apps/sample-data/make_sample_data.py
--
-- The approval hashes are SHA-256 of the same snapshot the API builds; the integration test
-- services/api/tests/integration/test_seed.py checks they still match.

BEGIN;

-- sessions and messages -------------------------------------------------------------------

INSERT INTO sessions (session_id, interface, session_status, created_at) VALUES
  ('c0000000-0000-4000-8000-000000000001', 'web', 'ACTIVE', '2026-11-02T09:00:00Z');

INSERT INTO messages (message_id, session_id, sequence_no, role, content_masked, created_at) VALUES
  ('c1000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001', 1, 'user',
   'Test the Juice Shop demo at http://juice-shop.example:3000/ for common web bugs.',
   '2026-11-02T09:00:10Z'),
  ('c1000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000001', 2, 'assistant',
   'Plan: find open ports with nmap, scan the site with nuclei, then run a ZAP baseline scan.',
   '2026-11-02T09:05:00Z'),
  ('c1000000-0000-4000-8000-000000000003', 'c0000000-0000-4000-8000-000000000001', 3, 'user',
   'Approved. Go ahead with nuclei.',
   '2026-11-02T09:12:00Z');

-- assessment and scope --------------------------------------------------------------------

INSERT INTO assessments
  (assessment_id, engagement_code, name, type, assessment_status, created_by, created_at,
   updated_at, session_id)
VALUES
  ('a0000000-0000-4000-8000-000000000001', 'RCX-2026-0001', 'Juice Shop web test', 'web_url',
   'ACTIVE', 'demo-tester', '2026-11-02T09:02:00Z', '2026-11-02T09:04:00Z',
   'c0000000-0000-4000-8000-000000000001');

INSERT INTO scope_manifests
  (manifest_id, version, manifests_status, max_risk, allowed_tools, allowed_ports,
   allowed_actions, allowed_methods, starts_at, ends_at, limitations, decided_by, decided_at,
   session_id, assessment_id)
VALUES
  ('b0000000-0000-4000-8000-000000000001', 1, 'APPROVED', 'MEDIUM',
   '["NMAP", "NUCLEI", "ZAP"]', '[80, 443, 3000]', '["discovery", "scan", "validation"]',
   '["GET", "HEAD", "OPTIONS"]', '2026-11-01T00:00:00Z', '2026-12-31T23:59:00Z',
   'No denial of service. Do not touch the /ftp/ folder.', 'demo-tester',
   '2026-11-02T09:04:00Z', 'c0000000-0000-4000-8000-000000000001',
   'a0000000-0000-4000-8000-000000000001');

INSERT INTO scope_targets (scope_target_id, type, value, excluded, manifest_id) VALUES
  ('b1000000-0000-4000-8000-000000000001', 'url', 'http://juice-shop.example:3000/', false,
   'b0000000-0000-4000-8000-000000000001'),
  ('b1000000-0000-4000-8000-000000000002', 'ip', '192.0.2.10', false,
   'b0000000-0000-4000-8000-000000000001'),
  ('b1000000-0000-4000-8000-000000000003', 'url', 'http://juice-shop.example:3000/ftp/', true,
   'b0000000-0000-4000-8000-000000000001');

-- agent run (uses the built-in RECONIX provider the migration adds) ------------------------

INSERT INTO agent_runs
  (agent_run_id, model_name, agent_runs_status, started_at, finished_at, plan, session_id,
   assessment_id, llm_provider_id)
SELECT
  'd0000000-0000-4000-8000-000000000001', model_name, 'WAITING_APPROVAL',
  '2026-11-02T09:05:00Z', NULL,
  '{"task": "PLAN",
    "text": "Plan: find open ports with nmap, scan the site with nuclei, then run a ZAP baseline scan.",
    "steps": [
      {"order": 1, "title": "Find open ports", "phase": "discovery",
       "reason": "Know which services the host exposes.",
       "action": {"tool": "NMAP", "target": "192.0.2.10", "arguments": ["-sV", "-Pn", "-p", "80,443,3000"],
                  "is_validation": false, "finding_id": null}},
      {"order": 2, "title": "Scan the site for known bugs", "phase": "scan",
       "reason": "Nuclei templates cover common Juice Shop issues.",
       "action": {"tool": "NUCLEI", "target": "http://juice-shop.example:3000/", "arguments": ["-severity", "low,medium,high,critical"],
                  "is_validation": false, "finding_id": null}},
      {"order": 3, "title": "Run a ZAP baseline scan", "phase": "scan",
       "reason": "Passive checks for headers and cookies.",
       "action": {"tool": "ZAP", "target": "http://juice-shop.example:3000/", "arguments": [],
                  "is_validation": false, "finding_id": null}}
    ],
    "blocked": [], "draft": false, "proposed_action": null}',
  'c0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001',
  llm_provider_id
FROM llm_providers WHERE provider_type = 'RECONIX';

-- actions, approvals and tool runs -----------------------------------------------------------

INSERT INTO actions
  (action_id, tool, args, target, purpose, risk_level, action_status, guardrail_report, source,
   created_at, assessment_id, manifest_id, agent_run_id)
VALUES
  ('ac000000-0000-4000-8000-000000000001', 'NMAP', '["-sV", "-Pn", "-p", "80,443,3000"]',
   '192.0.2.10', 'discovery', 'LOW', 'COMPLETED',
   '{"decision": "ALLOW", "risk": "LOW", "blocked_by": null, "reason": null}', 'agent',
   '2026-11-02T09:05:10Z', 'a0000000-0000-4000-8000-000000000001',
   'b0000000-0000-4000-8000-000000000001', 'd0000000-0000-4000-8000-000000000001'),
  ('ac000000-0000-4000-8000-000000000002', 'NUCLEI', '["-severity", "low,medium,high,critical"]',
   'http://juice-shop.example:3000/', 'scan', 'MEDIUM', 'COMPLETED',
   '{"decision": "ALLOW", "risk": "MEDIUM", "blocked_by": null, "reason": null}', 'agent',
   '2026-11-02T09:10:00Z', 'a0000000-0000-4000-8000-000000000001',
   'b0000000-0000-4000-8000-000000000001', 'd0000000-0000-4000-8000-000000000001'),
  ('ac000000-0000-4000-8000-000000000003', 'ZAP', '[]',
   'http://juice-shop.example:3000/', 'scan', 'MEDIUM', 'PENDING',
   '{"decision": "ALLOW", "risk": "MEDIUM", "blocked_by": null, "reason": null}', 'agent',
   '2026-11-02T09:20:00Z', 'a0000000-0000-4000-8000-000000000001',
   'b0000000-0000-4000-8000-000000000001', 'd0000000-0000-4000-8000-000000000001');

INSERT INTO approvals
  (approval_id, kind, subject_snapshot, subject_hash, risk_level, approval_status,
   confirmation_verified, decided_by, requested_at, decided_at, consumed_at, action_id,
   manifest_id)
VALUES
  -- the scope, approved and used at once
  ('ab000000-0000-4000-8000-000000000001', 'scope',
   '{"manifest_id": "b0000000-0000-4000-8000-000000000001", "version": 1, "max_risk": "MEDIUM",
     "allowed_tools": ["NMAP", "NUCLEI", "ZAP"],
     "allowed_actions": ["discovery", "scan", "validation"],
     "allowed_methods": ["GET", "HEAD", "OPTIONS"],
     "starts_at": "2026-11-01T00:00:00+00:00", "ends_at": "2026-12-31T23:59:00+00:00",
     "limitations": "No denial of service. Do not touch the /ftp/ folder.",
     "targets": [
       {"type": "ip", "value": "192.0.2.10", "excluded": false},
       {"type": "url", "value": "http://juice-shop.example:3000/", "excluded": false},
       {"type": "url", "value": "http://juice-shop.example:3000/ftp/", "excluded": true}
     ],
     "allowed_ports": [80, 443, 3000]}',
   'bcb399529f0180d1eb92e81f0b3067d5b47df3d2948793d5d044f6f91180f313', NULL, 'APPROVED', false, 'demo-tester',
   '2026-11-02T09:03:00Z', '2026-11-02T09:04:00Z', '2026-11-02T09:04:00Z', NULL,
   'b0000000-0000-4000-8000-000000000001'),
  -- the NUCLEI action, approved and used by its tool run
  ('ab000000-0000-4000-8000-000000000002', 'action',
   '{"tool": "NUCLEI", "target": "http://juice-shop.example:3000/",
     "arguments": ["-severity", "low,medium,high,critical"], "is_validation": false,
     "finding_id": null}',
   '1a28e59b82ad6ed6557a3b1eecb15af6f6eb6af72c3f5ff0ecaa8968b7b6ac2d', 'MEDIUM', 'APPROVED', false, 'demo-tester',
   '2026-11-02T09:10:00Z', '2026-11-02T09:12:00Z', '2026-11-02T09:12:05Z',
   'ac000000-0000-4000-8000-000000000002', NULL),
  -- the ZAP action, still waiting for a person
  ('ab000000-0000-4000-8000-000000000003', 'action',
   '{"tool": "ZAP", "target": "http://juice-shop.example:3000/", "arguments": [],
     "is_validation": false, "finding_id": null}',
   '74f98cfa9a4c466e2929032d9de222aae90a273bb04c69e69f06a2ee13ba37e6', 'MEDIUM', 'PENDING', false, NULL,
   '2026-11-02T09:20:00Z', NULL, NULL,
   'ac000000-0000-4000-8000-000000000003', NULL);

INSERT INTO tool_runs
  (tool_run_id, attempt_no, tool_run_status, exit_code, masked_count, request_count,
   output_masked, job_token_id, started_at, finished_at, action_id, approval_id)
VALUES
  ('e0000000-0000-4000-8000-000000000001', 1, 'COMPLETED', 0, 0, 0,
   'PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.27
443/tcp  closed https
3000/tcp open  http    Node.js Express framework',
   'e1000000-0000-4000-8000-000000000001', '2026-11-02T09:05:15Z', '2026-11-02T09:06:40Z',
   'ac000000-0000-4000-8000-000000000001', NULL),
  ('e0000000-0000-4000-8000-000000000002', 1, 'COMPLETED', 0, 1, 412,
   '[sqli-error-based] [http] [high] http://juice-shop.example:3000/rest/products/search?q=''
[xss-reflected] [http] [medium] http://juice-shop.example:3000/#/search?q=<script>
[http-missing-security-headers] [http] [low] http://juice-shop.example:3000/
Authorization: Bearer ••••',
   'e1000000-0000-4000-8000-000000000002', '2026-11-02T09:12:05Z', '2026-11-02T09:18:30Z',
   'ac000000-0000-4000-8000-000000000002', 'ab000000-0000-4000-8000-000000000002');

-- findings, sources, evidence and validation -------------------------------------------------

INSERT INTO findings
  (finding_id, code, title, target, description, severity_status, cvss_score, cwe_ids,
   owasp_id, cve_ids, impact, remediation, validation_status, finding_status, dedupe_key,
   created_at, assessment_id)
VALUES
  ('f0000000-0000-4000-8000-000000000001', 'RCX-001', 'SQL injection in product search',
   'http://juice-shop.example:3000/rest/products/search?q=',
   'The q parameter is put into a SQL query without escaping; a single quote returns a database error.',
   'HIGH', 8.6, '["CWE-89"]', '["A03:2021"]', '[]',
   'An attacker can read any table, including user accounts and password hashes.',
   'Use parameterised queries for the product search.',
   'CONFIRMED', 'OPEN', 'nuclei:sqli-error-based:juice-shop.example:3000/rest/products/search',
   '2026-11-02T09:18:31Z', 'a0000000-0000-4000-8000-000000000001'),
  ('f0000000-0000-4000-8000-000000000002', 'RCX-002', 'Reflected XSS in search',
   'http://juice-shop.example:3000/#/search?q=',
   'The search term is written back into the page without encoding.',
   'MEDIUM', 6.1, '["CWE-79"]', '["A03:2021"]', '[]',
   'A crafted link can run script in a signed-in user''s browser.',
   'Encode the search term before writing it into the page.',
   'UNCONFIRMED', 'OPEN', 'nuclei:xss-reflected:juice-shop.example:3000/#/search',
   '2026-11-02T09:18:31Z', 'a0000000-0000-4000-8000-000000000001'),
  ('f0000000-0000-4000-8000-000000000003', 'RCX-003', 'Missing security headers',
   'http://juice-shop.example:3000/',
   'The site sends no Content-Security-Policy or Strict-Transport-Security header.',
   'LOW', 3.1, '["CWE-693"]', '["A05:2021"]', '[]',
   'The browser has fewer defences against injected script and downgrade attacks.',
   'Add Content-Security-Policy and Strict-Transport-Security headers.',
   'UNCONFIRMED', 'OPEN', 'nuclei:http-missing-security-headers:juice-shop.example:3000/',
   '2026-11-02T09:18:31Z', 'a0000000-0000-4000-8000-000000000001'),
  ('f0000000-0000-4000-8000-000000000004', 'RCX-004', 'Open port 3000 (Node.js Express)',
   '192.0.2.10:3000',
   'Port 3000 is open and serves the Juice Shop app with Node.js Express.',
   'NONE', NULL, '[]', '[]', '[]', NULL, NULL,
   'UNCONFIRMED', 'OPEN', 'nmap:open-port:192.0.2.10:3000',
   '2026-11-02T09:06:41Z', 'a0000000-0000-4000-8000-000000000001');

INSERT INTO finding_sources (finding_id, tool_run_id) VALUES
  ('f0000000-0000-4000-8000-000000000001', 'e0000000-0000-4000-8000-000000000002'),
  ('f0000000-0000-4000-8000-000000000002', 'e0000000-0000-4000-8000-000000000002'),
  ('f0000000-0000-4000-8000-000000000003', 'e0000000-0000-4000-8000-000000000002'),
  ('f0000000-0000-4000-8000-000000000004', 'e0000000-0000-4000-8000-000000000001');

INSERT INTO evidences
  (evidence_id, kind, content, location, created_at, finding_id, tool_run_id)
VALUES
  ('f1000000-0000-4000-8000-000000000001', 'http_response',
   'HTTP/1.1 500 Internal Server Error
{"error": "SQLITE_ERROR: unrecognized token: \"''\""}',
   'http://juice-shop.example:3000/rest/products/search?q=''', '2026-11-02T09:18:31Z',
   'f0000000-0000-4000-8000-000000000001', 'e0000000-0000-4000-8000-000000000002'),
  ('f1000000-0000-4000-8000-000000000002', 'http_response',
   'HTTP/1.1 200 OK
...<span>Results for <script>alert(1)</script></span>...',
   'http://juice-shop.example:3000/#/search?q=<script>', '2026-11-02T09:18:31Z',
   'f0000000-0000-4000-8000-000000000002', 'e0000000-0000-4000-8000-000000000002'),
  ('f1000000-0000-4000-8000-000000000003', 'nmap_port',
   '3000/tcp open http Node.js Express framework',
   '192.0.2.10:3000', '2026-11-02T09:06:41Z',
   'f0000000-0000-4000-8000-000000000004', 'e0000000-0000-4000-8000-000000000001');

INSERT INTO validation_runs
  (validation_run_id, method, validation_status, reason, reviewed_by, reviewed_at, created_at,
   finding_id, tool_run_id)
VALUES
  ('f2000000-0000-4000-8000-000000000001', 'manual_review', 'CONFIRMED',
   'The database error appears with a single quote and goes away when it is escaped.',
   'demo-tester', '2026-11-02T09:25:00Z', '2026-11-02T09:25:00Z',
   'f0000000-0000-4000-8000-000000000001', NULL);

UPDATE findings SET reviewed_by = 'demo-tester', reviewed_at = '2026-11-02T09:25:00Z'
WHERE finding_id = 'f0000000-0000-4000-8000-000000000001';

COMMIT;
