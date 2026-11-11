/* A fake Core API for tests only (product code never imports it): answers in the exact shapes
   of docs/openapi.json (SessionCreated, AssessmentRowOut, FindingOut, the error shape), served
   through a stubbed `fetch`. Values are obvious fakes. */
import { vi } from "vitest";

export const ASSESSMENT_ID = "11111111-1111-4111-8111-111111111111";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const TOOL_RUN_ID = "33333333-3333-4333-8333-333333333333";
const AT = "2026-11-10T09:00:00Z";

export const assessmentRow = {
  assessment_id: ASSESSMENT_ID,
  engagement_code: "ENG-TEST",
  name: "Juice Shop web",
  type: "WEB",
  assessment_status: "ACTIVE",
  created_by: "tester@lab",
  created_at: AT,
  updated_at: AT,
  session_id: SESSION_ID,
  targets: ["http://10.10.0.5:3000"],
  finding_count: 2,
  worst_severity: "HIGH",
  pending_approval_count: 0,
};

const finding = {
  assessment_id: ASSESSMENT_ID,
  created_at: AT,
  cve_ids: [],
  cwe_ids: ["CWE-89"],
  owasp_id: ["A03:2021"],
  description: "The search parameter reaches the SQL query unescaped.",
  evidence: [
    { evidence_id: "44444444-4444-4444-8444-444444444444", kind: "REQUEST", content: "GET /rest/products/search?q='", location: "q", created_at: AT, tool_run_id: TOOL_RUN_ID },
  ],
  finding_status: "OPEN",
  impact: "Read any table.",
  latest_validation: null,
  remediation: "Use bound parameters.\nValidate the input.",
  reviewed_at: null,
  reviewed_by: null,
  source_tool_run_ids: [TOOL_RUN_ID],
  tools: ["sqlmap"],
};

export const findings = [
  { ...finding, finding_id: "55555555-5555-4555-8555-555555555555", code: "F-001", title: "SQL injection in search", target: "http://10.10.0.5:3000/rest/products/search", severity_status: "HIGH", cvss_score: "8.6", validation_status: "CONFIRMED" },
  { ...finding, finding_id: "66666666-6666-4666-8666-666666666666", code: "F-002", title: "Unrated banner", target: "http://10.10.0.5:3000", severity_status: "UNKNOWN", cvss_score: null, validation_status: "UNCONFIRMED", finding_status: "FALSE_POSITIVE", cwe_ids: [], owasp_id: [], evidence: [], impact: null, remediation: null },
];

export const FAKE_TOKEN = "fake-session-token-for-tests";

type Answer = { status: number; body: unknown };
export interface FakeApi {
  calls: { method: string; path: string; auth: string | null; body: unknown }[];
  /** Override the answer for one path (after /api/v1, query included). */
  answers: Map<string, Answer[]>;
  down: boolean;
}

/** Stub `fetch` with the fake API; returns its call log and per-path answer queue. */
export function installFakeApi(): FakeApi {
  const api: FakeApi = { calls: [], answers: new Map(), down: false };
  vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
    if (api.down) throw new TypeError("fetch failed");
    const path = new URL(url).pathname.replace(/^\/api\/v1/, "") + new URL(url).search;
    const headers = (init.headers ?? {}) as Record<string, string>;
    api.calls.push({ method: init.method ?? "GET", path, auth: headers.Authorization ?? null, body: init.body ? JSON.parse(String(init.body)) : null });
    const queued = api.answers.get(path)?.shift();
    const a: Answer = queued ?? defaultAnswer(init.method ?? "GET", path);
    return new Response(JSON.stringify(a.body), { status: a.status, headers: { "Content-Type": "application/json" } });
  });
  return api;
}

function defaultAnswer(method: string, path: string): Answer {
  if (method === "POST" && path === "/sessions")
    return { status: 200, body: { session_id: SESSION_ID, interface: "web", session_status: "ACTIVE", created_at: AT, closed_at: null, token: FAKE_TOKEN } };
  if (path === "/assessments") return { status: 200, body: [assessmentRow] };
  if (path.startsWith("/findings")) return { status: 200, body: findings };
  return { status: 404, body: { code: "NOT_FOUND", message: "Not found.", details: {} } };
}
