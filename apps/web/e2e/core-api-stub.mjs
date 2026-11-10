// A stand-in for the local Core API, for the e2e tests (playwright.config.ts starts it). It serves
// the sample runs (sample-data/) in the API's own shapes (docs/openapi.json: SessionCreated,
// AssessmentRowOut, FindingOut, the error shape), so the Findings view shows the same findings
// the specs read from the files (e2e/support.ts `sample()`):
//   POST /api/v1/sessions                 a token (any body with interface "web")
//   GET  /api/v1/assessments              one row per sample run, newest first (as store.ts sorts)
//   GET  /api/v1/findings[?assessment_id] their findings, the informational ones left out
// Every GET needs a token it issued (401 INVALID_TOKEN otherwise). Test code only.
import { readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { apiId } from "./core-api-ids.mjs";

const port = Number(process.env.CORE_API_STUB_PORT || 3193);
const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "sample-data");
const SESSION_ID = "00000000-0000-4000-8000-0000000000e2";
const tokens = new Set();

const isInfo = (f) => [f.severity, f.severity_override ?? "", f.effective_severity ?? ""].some((s) => s.trim().toUpperCase() === "INFO");
const TRIAGE = { open: "OPEN", fixed: "FIXED", "false-positive": "FALSE_POSITIVE" };
const cap = (s) => s[0].toUpperCase() + s.slice(1);

const runs = readdirSync(dir)
  .filter((n) => n.endsWith(".json"))
  .map((n) => JSON.parse(readFileSync(path.join(dir, n), "utf8")))
  .sort((a, b) => b.created_at.localeCompare(a.created_at) || b.uid.localeCompare(a.uid));

function findingOut(a, f, i) {
  const id = apiId(a.uid);
  const cwe = f.cwe?.length ? f.cwe : (f.references ?? []).filter((r) => /^CWE-\d+$/.test(r));
  return {
    finding_id: `${id.slice(0, 24)}${String(i).padStart(12, "0")}`,
    assessment_id: id,
    code: /^\d+$/.test(f.id) ? `F-${f.id}` : f.id,
    title: f.title,
    target: f.affected_url || f.path || "",
    description: f.description ?? "",
    severity_status: f.effective_severity || f.severity_override || f.severity,
    cvss_score: f.cvss_score > 0 ? String(f.cvss_score) : null,
    cwe_ids: cwe,
    owasp_id: f.owasp ?? [],
    cve_ids: f.cve ?? [],
    impact: f.impact || null,
    remediation: (f.remediation ?? "").split(/;\s+/).map((r) => r.trim()).filter(Boolean).map(cap).join("\n") || null,
    validation_status: f.validation || "UNCONFIRMED",
    finding_status: TRIAGE[f.status] ?? "OPEN",
    reviewed_by: null,
    reviewed_at: null,
    created_at: a.created_at,
    latest_validation: null,
    source_tool_run_ids: [],
    tools: f.tool ? [f.tool] : [],
    evidence: (f.evidence ?? []).map((text, n) => ({
      evidence_id: `${id.slice(0, 24)}${String(i * 100 + n).padStart(12, "0")}`,
      kind: "TEXT",
      content: text,
      location: null,
      created_at: a.created_at,
      tool_run_id: SESSION_ID,
    })),
  };
}

const findings = runs.flatMap((a) => a.findings.filter((f) => !isInfo(f)).map((f, i) => findingOut(a, f, i)));

const assessments = runs.map((a) => {
  const mine = findings.filter((f) => f.assessment_id === apiId(a.uid) && f.finding_status !== "FALSE_POSITIVE");
  return {
    assessment_id: apiId(a.uid),
    engagement_code: a.assessment_id || a.uid,
    name: a.label || a.uid,
    type: "WEB",
    assessment_status: "ACTIVE",
    created_by: "tester@lab",
    created_at: a.created_at,
    updated_at: a.saved_at || a.created_at,
    session_id: SESSION_ID,
    targets: a.target ? [a.target] : [],
    finding_count: mine.length,
    worst_severity: mine[0]?.severity_status ?? null,
    pending_approval_count: 0,
  };
});

const send = (res, status, body) => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
  if (req.method === "GET" && url.pathname === "/") return send(res, 200, { status: "OK" }); // Playwright's ready check
  if (req.method === "POST" && url.pathname === "/api/v1/sessions") {
    const token = `e2e-core-token-${tokens.size + 1}`;
    tokens.add(token);
    return send(res, 200, { session_id: SESSION_ID, interface: "web", session_status: "ACTIVE", created_at: new Date().toISOString(), closed_at: null, token });
  }
  const auth = (req.headers.authorization ?? "").replace(/^Bearer /, "");
  if (!tokens.has(auth)) return send(res, 401, { code: "INVALID_TOKEN", message: "The session token is not valid.", details: {} });
  if (req.method === "GET" && url.pathname === "/api/v1/assessments") return send(res, 200, assessments);
  if (req.method === "GET" && url.pathname === "/api/v1/findings") {
    const id = url.searchParams.get("assessment_id");
    return send(res, 200, id ? findings.filter((f) => f.assessment_id === id) : findings);
  }
  send(res, 404, { code: "NOT_FOUND", message: "Not found.", details: {} });
}).listen(port, "127.0.0.1");
