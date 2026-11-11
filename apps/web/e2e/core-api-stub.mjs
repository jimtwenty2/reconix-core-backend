// A stand-in for the local Core API, for the e2e tests (playwright.config.ts starts it). It serves
// the sample runs (sample-data/) in the API's own shapes (docs/openapi.json: SessionCreated,
// AssessmentRowOut, FindingOut, the error shape), so the Findings view shows the same findings
// the specs read from the files (e2e/support.ts `sample()`):
//   POST /api/v1/sessions                 a token (any body with interface "web")
//   GET  /api/v1/assessments              one row per sample run, newest first (as store.ts sorts)
//   GET  /api/v1/findings[?assessment_id] their findings, the informational ones left out
// and what the AI Assistant needs from the API:
//   sessions (one per conversation): open, list, read, messages, agent-runs, resume, close
//   POST /api/v1/sessions/{id}/chat/stream  asks the active provider's model (e2e/llm-stub.mjs)
//        as the real API's agent does, and streams it as PIECE, then DONE (or ERROR)
//   /api/v1/llm-providers: list, add, change, delete, activate, test, models
//   GET  /api/v1/assessments/{id}/overview|actions|timeline, /api/v1/approvals
// Every call but opening a session needs a token it issued (401 INVALID_TOKEN otherwise).
// Test code only.
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { apiId } from "./core-api-ids.mjs";

const port = Number(process.env.CORE_API_STUB_PORT || 3193);
const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "sample-data");
const SESSION_ID = "00000000-0000-4000-8000-0000000000e2";
const tokens = new Map(); // token -> session id
const sessions = new Map(); // session id -> SessionRead
const messages = []; // MessageOut, every session
const providers = []; // LlmProviderOut
/** What GET /llm-providers/{id}/models answers for a cloud service. */
const CLOUD_MODELS = ["gpt-4.1", "gpt-4o", "gpt-4o-mini"];

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
  res.end(body === undefined ? undefined : JSON.stringify(body));
};
const refuse = (res, status, code, message) => send(res, status, { code, message, details: {} });
const now = () => new Date().toISOString();

function open(iface) {
  const session = { session_id: randomUUID(), interface: iface, session_status: "ACTIVE", created_at: now(), closed_at: null };
  sessions.set(session.session_id, session);
  const token = `e2e-core-token-${randomUUID()}`;
  tokens.set(token, session.session_id);
  return { ...session, token };
}

function save(sessionId, role, content) {
  const sequence_no = messages.filter((m) => m.session_id === sessionId).length + 1;
  const message = { message_id: randomUUID(), sequence_no, role, content_masked: content, created_at: now(), session_id: sessionId };
  messages.push(message);
  return message;
}

const overview = (row) => ({
  assessment: { ...row },
  targets: row.targets,
  finding_count: row.finding_count,
  findings_by_severity: {},
  findings_by_validation: {},
  findings_by_status: {},
  actions_by_status: {},
  plan_step_count: 0,
  plan_step_done_count: 0,
  tool_run_count: 0,
  request_count: 0,
  masked_count: 0,
  pending_approval_count: 0,
  first_started_at: null,
  last_finished_at: null,
  duration_seconds: 0,
  time_window_seconds: null,
  over_time_window: false,
});

/** Ask the active provider's model, as the real API's agent does, and stream its words. */
async function chat(res, sessionId, content) {
  const active = providers.find((p) => p.is_active);
  if (!active) return refuse(res, 409, "NO_ACTIVE_PROVIDER", "Choose a model first.");
  const earlier = messages.filter((m) => m.session_id === sessionId).map((m) => ({ role: m.role, content: m.content_masked }));
  const message = save(sessionId, "user", content);
  const system = `You answer questions about the assessments. ALL SAVED ASSESSMENTS: ${assessments.length}`;
  const event = (name, data) => res.write(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`);
  let upstream;
  try {
    upstream = await fetch(`${active.base_url}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: active.model_name, stream: true, messages: [{ role: "system", content: system }, ...earlier, { role: "user", content }] }),
    });
  } catch {
    upstream = null;
  }
  res.writeHead(200, { "Content-Type": "text/event-stream" });
  if (!upstream || !upstream.ok || !upstream.body) {
    event("ERROR", { code: "MODEL_UNAVAILABLE", message: "The model did not answer.", details: {} });
    return res.end();
  }
  let text = "";
  let buffer = "";
  const stop = new AbortController();
  res.on("close", () => stop.abort());
  try {
    for await (const piece of upstream.body) {
      if (stop.signal.aborted) break;
      buffer += Buffer.from(piece).toString("utf8");
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith("data: ") || line === "data: [DONE]") continue;
        const words = JSON.parse(line.slice(6)).choices?.[0]?.delta?.content ?? "";
        if (!words) continue;
        text += words;
        event("PIECE", { text: words });
      }
    }
  } catch {
    // the client went away (Stop): nothing is saved, as the real API saves nothing half-written
  }
  if (res.destroyed || stop.signal.aborted) return;
  if (!text.trim()) {
    event("ERROR", { code: "EMPTY_RESPONSE", message: "The model gave an empty answer.", details: {} });
    return res.end();
  }
  const reply = save(sessionId, "assistant", text);
  event("DONE", { message, reply, agent_run_id: randomUUID() });
  res.end();
}

async function provider(req, res, url, body, rest, row) {
  const m = req.method;
  if (m === "PATCH" && rest === "") {
    for (const key of ["display_name", "model_name", "base_url"]) if (key in body) row[key] = body[key];
    if ("api_key" in body) row.api_key_last4 = body.api_key ? String(body.api_key).slice(-4) : null;
    row.updated_at = now();
    return send(res, 200, row);
  }
  if (m === "DELETE" && rest === "") {
    if (row.is_active) return refuse(res, 409, "LLM_PROVIDER_IN_USE", "Choose another model before removing this one.");
    providers.splice(providers.indexOf(row), 1);
    res.writeHead(204);
    return res.end();
  }
  if (m === "POST" && rest === "/activate") {
    if (!row.is_local) return send(res, 200, { llm_provider: row, approval: { approval_id: randomUUID() } });
    for (const p of providers) p.is_active = p === row;
    return send(res, 200, { llm_provider: row, approval: null });
  }
  if (m === "POST" && rest === "/test") {
    const ok = await fetch(`${row.base_url}/models`).then((r) => r.ok).catch(() => false);
    return send(res, 200, { ok, model_name: row.model_name, latency_ms: 5, code: ok ? null : "MODEL_UNAVAILABLE", message: ok ? null : "The model did not answer." });
  }
  if (m === "GET" && rest === "/models") {
    if (["OPENAI", "ANTHROPIC", "DEEPSEEK"].includes(row.provider_type)) return send(res, 200, { models: CLOUD_MODELS });
    const listed = await fetch(`${row.base_url}/models`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
    if (!listed) return refuse(res, 503, "MODEL_UNAVAILABLE", "The server did not answer with its models.");
    return send(res, 200, { models: listed.data.map((d) => d.id) });
  }
  return refuse(res, 404, "NOT_FOUND", "Not found.");
}

async function handle(req, res, raw) {
  const url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
  const m = req.method;
  const p = url.pathname.replace(/^\/api\/v1/, "");
  const body = raw ? JSON.parse(raw) : {};
  if (m === "GET" && url.pathname === "/") return send(res, 200, { status: "OK" }); // Playwright's ready check
  if (m === "POST" && p === "/sessions") return send(res, 201, open(body.interface ?? "web"));
  // test only: forget every provider, as a fresh API has none (e2e/models.ts clearModels)
  if (m === "POST" && url.pathname === "/__e2e/reset-providers") {
    providers.length = 0;
    return send(res, 200, { ok: true });
  }
  if (m === "POST" && p === "/sessions/web-sign-in") return refuse(res, 401, "INVALID_SIGN_IN_CODE", "The sign-in code is not valid.");
  const me = tokens.get((req.headers.authorization ?? "").replace(/^Bearer /, ""));
  if (!me) return refuse(res, 401, "INVALID_TOKEN", "The session token is not valid.");

  if (m === "GET" && p === "/sessions") {
    const want = (key, value) => !url.searchParams.get(key) || url.searchParams.get(key) === value;
    return send(res, 200, [...sessions.values()].filter((s) => want("interface", s.interface) && want("session_status", s.session_status)).reverse());
  }
  let hit = p.match(/^\/sessions\/([^/]+)(\/.*)?$/);
  if (hit) {
    const [, id, rest = ""] = hit;
    const session = sessions.get(id);
    if (!session) return refuse(res, 404, "SESSION_NOT_FOUND", "No session has this id.");
    if (m === "GET" && rest === "") return send(res, 200, session);
    if (m === "GET" && rest === "/messages") return send(res, 200, messages.filter((x) => x.session_id === id));
    if (m === "GET" && rest === "/agent-runs") return send(res, 200, []);
    if (m === "POST" && rest === "/resume") {
      if (session.session_status === "CLOSED") return refuse(res, 409, "SESSION_CLOSED", "This session is already closed.");
      const token = `e2e-core-token-${randomUUID()}`;
      tokens.set(token, id);
      return send(res, 201, { ...session, token });
    }
    if (m === "POST" && rest === "/close") {
      if (id !== me) return refuse(res, 403, "NOT_YOUR_SESSION", "You can only close your own session.");
      Object.assign(session, { session_status: "CLOSED", closed_at: now() });
      return send(res, 200, session);
    }
    if (m === "POST" && rest === "/chat/stream") {
      if (id !== me) return refuse(res, 403, "NOT_YOUR_SESSION", "You can only write in your own session.");
      return chat(res, id, String(body.content ?? ""));
    }
  }

  if (m === "GET" && p === "/assessments") return send(res, 200, assessments);
  hit = p.match(/^\/assessments\/([^/]+)\/(overview|actions|timeline)$/);
  if (m === "GET" && hit) {
    const row = assessments.find((a) => a.assessment_id === hit[1]);
    if (!row) return refuse(res, 404, "ASSESSMENT_NOT_FOUND", "No assessment has this id.");
    if (hit[2] === "overview") return send(res, 200, overview(row));
    if (hit[2] === "actions") return send(res, 200, []);
    return send(res, 200, { events: [], has_older: false });
  }
  if (m === "GET" && p === "/findings") {
    const id = url.searchParams.get("assessment_id");
    return send(res, 200, id ? findings.filter((f) => f.assessment_id === id) : findings);
  }
  if (m === "GET" && p === "/approvals") return send(res, 200, []);

  if (m === "GET" && p === "/llm-providers") return send(res, 200, providers);
  if (m === "POST" && p === "/llm-providers") {
    const local = body.provider_type === "OLLAMA" || /^http:\/\/(127\.0\.0\.1|localhost)[:/]/.test(body.base_url ?? "");
    const row = {
      llm_provider_id: randomUUID(),
      provider_type: body.provider_type,
      display_name: body.display_name,
      base_url: body.base_url ?? null,
      api_key_last4: body.api_key ? String(body.api_key).slice(-4) : null,
      model_name: body.model_name,
      is_active: false,
      is_local: local,
      archived_at: null,
      created_by: "tester@lab",
      created_at: now(),
      updated_at: now(),
    };
    providers.push(row);
    return send(res, 201, row);
  }
  hit = p.match(/^\/llm-providers\/([^/]+)(\/.*)?$/);
  if (hit) {
    const row = providers.find((x) => x.llm_provider_id === hit[1]);
    if (!row) return refuse(res, 404, "LLM_PROVIDER_NOT_FOUND", "No provider has this id.");
    return provider(req, res, url, body, hit[2] ?? "", row);
  }
  refuse(res, 404, "NOT_FOUND", "Not found.");
}

createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => handle(req, res, raw).catch(() => res.headersSent || refuse(res, 500, "STUB_ERROR", "The stub failed.")));
}).listen(port, "127.0.0.1");
