/* The AI Assistant's routes on the Core API (lib/api/): a question becomes a new web session
   and its chat stream, the conversation list and reads come from the API's sessions and
   messages, delete closes the session, and the model picker drives /llm-providers. A fake
   Core API (tests/fakes/core-api-server.ts) runs on a free local port. */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { pickCards } from "@/lib/assistant/cards";
import { buildContext } from "@/lib/assistant/context";
import { type CardOf, type Frame, parseFrame } from "@/lib/assistant/protocol";
import { COOKIE, sessionValue } from "@/lib/auth/session";
import { type FakeCore, startFakeCore } from "./fakes/core-api-server";

const TOKEN = "route-test-token-0123456789";
let cookie = "";
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (name: string) => (name === COOKIE && cookie ? { value: cookie } : undefined) }) }));

const { POST } = await import("@/app/api/assistant/route");
const list = await import("@/app/api/assistant/conversations/route");
const one = await import("@/app/api/assistant/conversations/[id]/route");
const models = await import("@/app/api/assistant/models/route");
const provider = await import("@/app/api/assistant/models/[id]/route");
const active = await import("@/app/api/assistant/models/active/route");
const probe = await import("@/app/api/assistant/models/test/route");
const fetchRoute = await import("@/app/api/assistant/models/fetch/route");
const connectRoute = await import("@/app/api/assistant/models/connect/route");
const { resetSessions, signInWithCode } = await import("@/lib/api/sessions");

let core: FakeCore;
beforeAll(async () => {
  core = await startFakeCore();
});
afterAll(() => core.close());

const saved = { ...process.env };
let clock = Date.now();
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime((clock += 120_000)); // a new rate-limit minute per test
  process.env.RECONIX_WEB_TOKEN = TOKEN;
  process.env.RECONIX_DATA_DIR = "sample-data";
  process.env.RECONIX_CORE_API = core.url;
  cookie = sessionValue(TOKEN);
  resetSessions();
  core.sessions.clear();
  core.tokens.clear();
  core.messages.length = 0;
  core.providers.length = 0;
  core.calls.length = 0;
  core.agent = { pieces: ["Two ", "approvals"], reply: "Two approvals wait." };
  core.runs.clear();
  core.listFails = false;
  core.assessments.length = 0;
  core.approvals.length = 0;
});
afterEach(() => {
  vi.useRealTimers();
  process.env = { ...saved };
});

const ORIGIN = "http://127.0.0.1:3100";
const request = (url: string, init: RequestInit & { origin?: string | null } = {}) => {
  const headers: Record<string, string> = { host: "127.0.0.1:3100", "content-type": "application/json" };
  if (init.origin !== null) headers.origin = init.origin ?? ORIGIN;
  return new Request(`http://127.0.0.1:3100${url}`, { ...init, headers });
};
const ctx = (id: string) => ({ params: Promise.resolve({ id }) });
const ask = (body: unknown) => POST(request("/api/assistant", { method: "POST", body: JSON.stringify(body) }));
const framesOf = async (res: Response) => (await res.text()).split("\n").map(parseFrame).filter((f): f is Frame => f !== null);

/** A local model, added and made active through the picker's route. */
async function addLocalModel() {
  const res = await models.POST(request("/api/assistant/models", { method: "POST", body: JSON.stringify({ name: "Ollama", preset: "ollama", baseUrl: "http://localhost:11434", models: ["llama3.2"], activate: true }) }));
  expect(res.status).toBe(201);
  return res.json();
}

describe("asking", () => {
  it("starts a web session, streams the agent's pieces, then the saved reply", async () => {
    await addLocalModel();
    const res = await ask({ uid: null, question: "What waits on my approval? key sk-abcdefgh12345678" });
    expect(res.status).toBe(200);
    const id = res.headers.get("x-conversation-id")!;
    const frames = await framesOf(res);
    expect(frames[0]).toMatchObject({ t: "meta", conversationId: id });
    expect(frames.filter((f) => f.t === "text").map((f) => (f as { delta: string }).delta).join("")).toBe("Two approvals");
    expect(frames).toContainEqual({ t: "final", text: "Two approvals wait." });
    expect(frames.at(-1)).toEqual({ t: "done" });
    const opened = core.calls.find((c) => c.path === "/sessions" && c.method === "POST")!;
    expect(opened.body).toMatchObject({ interface: "web" });
    const chat = core.calls.find((c) => c.path.endsWith("/chat/stream"))!;
    expect(chat.path).toBe(`/sessions/${id}/chat/stream`);
    expect(core.tokens.get(chat.token)).toBe(id); // asked as the conversation's own session
  });

  it("sends the knowledge the answer cites as one sources frame, and none when it cites nothing", async () => {
    await addLocalModel();
    const cited = { ref_id: "CVE-2021-44228", title: "Apache Log4j2 JNDI features remote code execution", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", source: "CVE", section: "Description" };
    core.agent = { pieces: ["Log4j "], reply: "Log4j is the one.", sources: [cited] };
    const frames = await framesOf(await ask({ uid: null, question: "What is CVE-2021-44228?" }));
    expect(frames).toContainEqual({ t: "sources", items: [cited] });
    core.agent = { pieces: [], reply: "Nothing cited." };
    const plain = await framesOf(await ask({ uid: null, question: "And now?" }));
    expect(plain.some((f) => f.t === "sources")).toBe(false);
  });

  it("continues the same conversation in the same session", async () => {
    await addLocalModel();
    const id = (await ask({ uid: null, question: "First" })).headers.get("x-conversation-id")!;
    const res = await ask({ conversationId: id, uid: null, question: "Second" });
    expect(res.headers.get("x-conversation-id")).toBe(id);
    await res.text();
    expect(core.messages.filter((m) => m.session_id === id && m.role === "user").map((m) => m.content_masked)).toEqual(["First", "Second"]);
  });

  it("keeps the asked assessment uid in meta scope instead of resetting to all runs", async () => {
    await addLocalModel();
    const uid = "20261105-120000-0001_target";
    const frames = await framesOf(await ask({ uid, question: "Summarize this assessment" }));
    expect(frames[0]).toMatchObject({ t: "meta", scope: { uid } });
  });

  it("passes the API's refusal on (no model: 503) and its stream error", async () => {
    const refused = await ask({ uid: null, question: "Hi" });
    expect(refused.status).toBe(503);
    expect((await refused.json()).detail).toBe("Choose a model first.");

    await addLocalModel();
    core.agent = { pieces: [], error: "The model is not reachable." };
    const frames = await framesOf(await ask({ uid: null, question: "Hi" }));
    expect(frames).toContainEqual({ t: "error", detail: "The model is not reachable." });
  });

  it("says so when the Core API is not running (503)", async () => {
    process.env.RECONIX_CORE_API = "http://127.0.0.1:1";
    const res = await ask({ uid: null, question: "Hi" });
    expect(res.status).toBe(503);
    expect((await res.json()).detail).toMatch(/Core API is not running/);
  });

  it("refuses an address that is not this computer", async () => {
    process.env.RECONIX_CORE_API = "http://example.com:8000";
    const res = await ask({ uid: null, question: "Hi" });
    expect(res.status).toBe(503);
    expect(core.calls).toHaveLength(0);
  });

  it("a conversation from before a restart is resumed and goes on (API or dashboard restart)", async () => {
    await addLocalModel();
    const id = (await ask({ uid: null, question: "Before" })).headers.get("x-conversation-id")!;
    core.restart(); // the API forgot every token
    const afterApi = await ask({ conversationId: id, uid: null, question: "After the API" });
    expect(afterApi.status).toBe(200);
    await afterApi.text();
    resetSessions(); // the dashboard forgot its tokens
    const afterWeb = await ask({ conversationId: id, uid: null, question: "After the dashboard" });
    expect(afterWeb.status).toBe(200);
    await afterWeb.text();
    expect(core.messages.filter((m) => m.session_id === id && m.role === "user").map((m) => m.content_masked)).toEqual(["Before", "After the API", "After the dashboard"]);
    expect(core.calls.filter((c) => c.path === `/sessions/${id}/resume`)).toHaveLength(2);
    // and it can be deleted
    expect((await one.DELETE(request(`/api/assistant/conversations/${id}`, { method: "DELETE" }), ctx(id))).status).toBe(200);
  });

  it("keeps the locks: no session 401, another origin 403", async () => {
    cookie = "";
    expect((await ask({ uid: null, question: "Hi" })).status).toBe(401);
    cookie = sessionValue(TOKEN);
    const res = await POST(request("/api/assistant", { method: "POST", body: JSON.stringify({ uid: null, question: "Hi" }), origin: "http://evil.example" }));
    expect(res.status).toBe(403);
    expect(core.calls).toHaveLength(0);
  });
});

describe("conversations", () => {
  it("lists the open web sessions that hold messages, titled by the first question", async () => {
    await addLocalModel();
    const id = (await ask({ uid: null, question: "Which hosts are in scope?" })).headers.get("x-conversation-id")!;
    const body = await (await list.GET(request("/api/assistant/conversations", { origin: null }))).json();
    expect(body.conversations).toEqual([expect.objectContaining({ id, title: "Which hosts are in scope?", count: 2 })]);

    const read = await (await one.GET(request(`/api/assistant/conversations/${id}`, { origin: null }), ctx(id))).json();
    expect(read.conversation.messages.map((m: { role: string; content: string }) => [m.role, m.content])).toEqual([
      ["user", "Which hosts are in scope?"],
      ["assistant", "Two approvals wait."],
    ]);
  });

  it("a question the API kept without an answer reads back with an error reply (Retry)", async () => {
    await addLocalModel();
    core.agent = { pieces: [], error: "The model is not reachable." };
    const id = (await ask({ uid: null, question: "Unanswered" })).headers.get("x-conversation-id")!;
    const read = await (await one.GET(request(`/api/assistant/conversations/${id}`, { origin: null }), ctx(id))).json();
    expect(read.conversation.messages).toEqual([
      expect.objectContaining({ role: "user", content: "Unanswered" }),
      expect.objectContaining({ role: "assistant", state: "error", detail: "No answer was saved for this question." }),
    ]);
  });

  it("a question whose answer is still being written says so, not that it failed", async () => {
    await addLocalModel();
    core.agent = { pieces: [], error: "Not yet." };
    const id = (await ask({ uid: null, question: "Slow one" })).headers.get("x-conversation-id")!;
    core.runs.set(id, "RUNNING");
    const read = await (await one.GET(request(`/api/assistant/conversations/${id}`, { origin: null }), ctx(id))).json();
    expect(read.conversation.messages.at(-1)).toMatchObject({ role: "assistant", state: "error", detail: expect.stringMatching(/still being written/) });
  });

  it("delete closes the session; rename is refused", async () => {
    await addLocalModel();
    const id = (await ask({ uid: null, question: "Hello" })).headers.get("x-conversation-id")!;
    expect((await one.PATCH(request(`/api/assistant/conversations/${id}`, { method: "PATCH", body: "{}" }))).status).toBe(405);
    expect((await one.DELETE(request(`/api/assistant/conversations/${id}`, { method: "DELETE" }), ctx(id))).status).toBe(200);
    expect(core.sessions.get(id)?.session_status).toBe("CLOSED");
    expect((await one.GET(request(`/api/assistant/conversations/${id}`, { origin: null }), ctx(id))).status).toBe(404);
  });

  it("a 401 on the main session opens a new one once", async () => {
    await (await list.GET(request("/api/assistant/conversations", { origin: null }))).json();
    core.restart();
    const res = await list.GET(request("/api/assistant/conversations", { origin: null }));
    expect(res.status).toBe(200);
  });
});

describe("sign-in code", () => {
  it("is traded once for the main session", async () => {
    core.codes.add("one-time-code");
    resetSessions("one-time-code");
    await signInWithCode();
    await list.GET(request("/api/assistant/conversations", { origin: null }));
    expect(core.calls.filter((c) => c.path === "/sessions/web-sign-in")).toHaveLength(1);
    expect(core.calls.some((c) => c.path === "/sessions" && c.method === "POST")).toBe(false);
  });

  it("an expired code falls back to a new session", async () => {
    resetSessions("expired-code");
    expect((await list.GET(request("/api/assistant/conversations", { origin: null }))).status).toBe(200);
    expect(core.calls.some((c) => c.path === "/sessions" && c.method === "POST")).toBe(true);
  });
});

describe("the model picker", () => {
  it("adds a local model as one API row and makes it active", async () => {
    const view = await addLocalModel();
    expect(core.calls.find((c) => c.path === "/llm-providers" && c.method === "POST")!.body).toEqual({ provider_type: "OLLAMA", display_name: "Ollama", model_name: "llama3.2", base_url: null }); // the default address: the API uses RECONIX_OLLAMA_URL
    expect(view.providers).toHaveLength(1);
    expect(view.providers[0]).toMatchObject({ preset: "ollama", models: ["llama3.2", "qwen:7b"], keySaved: false, local: true }); // its saved model first, then what it lists
    expect(view.summary).toMatchObject({ configured: true, name: "llama3.2" });
  });

  it("never returns the key, and a cloud model waits for its approval (409)", async () => {
    const res = await models.POST(request("/api/assistant/models", { method: "POST", body: JSON.stringify({ name: "OpenAI", preset: "openai", baseUrl: "https://api.openai.com/v1", models: ["gpt-4o"], apiKey: "sk-test-0123456789abcdef" }) }));
    const view = await res.json();
    expect(JSON.stringify(view)).not.toContain("0123456789abcdef");
    expect(view.providers[0]).toMatchObject({ preset: "openai", keySaved: true, local: false });
    expect(core.providers[0].base_url).toBeNull(); // a cloud service at its own address

    const id = view.providers[0].id;
    const chosen = await active.PUT(request("/api/assistant/models/active", { method: "PUT", body: JSON.stringify({ providerId: id, model: "gpt-4o" }) }));
    expect(chosen.status).toBe(409);
    expect((await chosen.json()).detail).toMatch(/^Approve this model in the TUI first/);
    expect(core.providers[0].is_active).toBe(false);
  });

  it("changes, tests, lists and removes a saved provider", async () => {
    const id = (await addLocalModel()).providers[0].id;
    const changed = await (await provider.PATCH(request(`/api/assistant/models/${id}`, { method: "PATCH", body: JSON.stringify({ name: "Home GPU" }) }), ctx(id))).json();
    expect(changed.providers[0].name).toBe("Home GPU");

    const tested = await (await probe.POST(request("/api/assistant/models/test", { method: "POST", body: JSON.stringify({ providerId: id }) }))).json();
    expect(tested).toEqual({ ok: true, detail: "It answered in 42 ms." });
    const fetched = await (await fetchRoute.POST(request("/api/assistant/models/fetch", { method: "POST", body: JSON.stringify({ providerId: id }) }))).json();
    expect(fetched).toEqual({ models: ["llama3.2", "qwen:7b"] });
    const unsaved = await (await fetchRoute.POST(request("/api/assistant/models/fetch", { method: "POST", body: JSON.stringify({ baseUrl: "http://127.0.0.1:1234/v1" }) }))).json();
    expect(unsaved.listed).toBe(false);

    // in use: the API removes the active row too, and leaves no model active
    core.calls.length = 0;
    const removed = await (await provider.DELETE(request(`/api/assistant/models/${id}`, { method: "DELETE" }), ctx(id))).json();
    expect(core.calls.filter((c) => c.method === "DELETE")).toHaveLength(1);
    expect(removed.providers).toEqual([]);
    expect(removed.summary.configured).toBe(false);
    expect(core.providers.some((p) => p.is_active)).toBe(false);
  });

  it("gives the rate slot back: many fetches and tests in a row all answer", async () => {
    const id = (await addLocalModel()).providers[0].id;
    for (let i = 0; i < 5; i++) {
      const fetched = await fetchRoute.POST(request("/api/assistant/models/fetch", { method: "POST", body: JSON.stringify({ providerId: id }) }));
      expect(fetched.status).toBe(200);
      const tested = await probe.POST(request("/api/assistant/models/test", { method: "POST", body: JSON.stringify({ providerId: id }) }));
      expect(tested.status).toBe(200);
    }
  });

  const connect = (body: unknown) => connectRoute.POST(request("/api/assistant/models/connect", { method: "POST", body: JSON.stringify(body) }));

  it("Test connection saves a new custom server, lists its models and needs no model name", async () => {
    const res = await connect({ name: "Custom OpenAI-compatible", preset: "custom", baseUrl: "http://127.0.0.1:1234/v1" });
    expect(res.status).toBe(200);
    const out = await res.json();
    expect(out).toMatchObject({ models: ["llama3.2", "qwen:7b"], detail: "Connected: 2 models found.", created: true });
    expect(core.providers).toHaveLength(1);
    expect(core.providers[0]).toMatchObject({ provider_type: "OPENAI_API_COMPATIBLE", base_url: "http://127.0.0.1:1234/v1", model_name: "llama3.2", is_active: false });
  });

  it("a connection that fails leaves nothing saved", async () => {
    core.listFails = true;
    const res = await connect({ name: "Ollama", preset: "ollama", baseUrl: "http://localhost:11434" });
    expect(res.status).toBe(503);
    expect((await res.json()).detail).toMatch(/did not answer/);
    expect(core.providers).toHaveLength(0);
  });

  it("a cloud service is tested with its key and offers the chat models it lists", async () => {
    const out = await (await connect({ name: "OpenAI", preset: "openai", baseUrl: "https://api.openai.com/v1", apiKey: "sk-test-0123456789abcdef" })).json();
    expect(out).toMatchObject({ models: ["gpt-4o-mini", "gpt-4o", "gpt-4.1"], created: true }); // no whisper, embeddings, images
    expect(out.detail).toMatch(/^Connected: gpt-4o-mini answered in \d+ ms\.$/);
    expect(JSON.stringify(out)).not.toContain("0123456789abcdef");
  });

  it("a cloud service that can't list its models offers its built-in ones", async () => {
    core.listFails = true;
    const view = await (await models.POST(request("/api/assistant/models", { method: "POST", body: JSON.stringify({ name: "OpenAI", preset: "openai", baseUrl: "https://api.openai.com/v1", models: ["gpt-4o-mini"], apiKey: "sk-test-0123456789abcdef" }) }))).json();
    expect(view.providers[0].models).toEqual(["gpt-4o-mini", "gpt-4o"]);
  });

  it("a saved provider is tested as saved, without saving another", async () => {
    const id = (await addLocalModel()).providers[0].id;
    const out = await (await connect({ name: "Ollama", preset: "ollama", baseUrl: "http://localhost:11434", providerId: id })).json();
    expect(out).toMatchObject({ providerId: id, created: false, models: ["llama3.2", "qwen:7b"] });
    expect(core.providers).toHaveLength(1);
  });

  it("one provider has many models: choosing another adds its row (key copied) and makes it active", async () => {
    const view = await (await models.POST(request("/api/assistant/models", { method: "POST", body: JSON.stringify({ name: "OpenAI", preset: "openai", baseUrl: "https://api.openai.com/v1", models: ["gpt-4o-mini"], apiKey: "sk-test-0123456789abcdef" }) }))).json();
    const id = view.providers[0].id;
    expect(view.providers[0].models).toEqual(["gpt-4o-mini", "gpt-4o", "gpt-4.1"]); // what the service lists for chat

    core.calls.length = 0;
    const res = await active.PUT(request("/api/assistant/models/active", { method: "PUT", body: JSON.stringify({ providerId: id, model: "gpt-4o" }) }));
    const added = core.calls.find((c) => c.path === "/llm-providers" && c.method === "POST")!;
    expect(added.body).toMatchObject({ provider_type: "OPENAI", model_name: "gpt-4o", copy_key_from: id });
    expect(added.body).not.toHaveProperty("api_key"); // the key is never sent again
    expect(res.status).toBe(409); // a cloud model waits for its own approval
    const after = await (await models.GET(request("/api/assistant/models", { origin: null }))).json();
    expect(after.providers).toHaveLength(1); // still one provider, with both models saved
    expect(after.providers[0].models).toEqual(["gpt-4o-mini", "gpt-4o", "gpt-4.1"]);
  });

  it("fast=1 returns saved providers without probing live /models lists", async () => {
    await addLocalModel();
    core.calls.length = 0;
    const fast = await (await models.GET(request("/api/assistant/models?fast=1", { origin: null }))).json();
    expect(fast.providers).toHaveLength(1);
    expect(fast.providers[0].models).toEqual(["llama3.2"]);
    expect(core.calls.some((c) => c.path.endsWith("/models"))).toBe(false);
  });

  it("lists only models that can chat: embedding models are left out", async () => {
    const { chatModels } = await import("@/lib/api/models");
    expect(chatModels(["google/gemma-4-e4b", "text-embedding-nomic-embed-text-v1.5", "bge-m3:embed", "bad name", "qwen:7b"])).toEqual(["google/gemma-4-e4b", "qwen:7b"]);
  });

  it("removing a provider removes every model it has", async () => {
    const id = (await addLocalModel()).providers[0].id;
    await provider.PATCH(request(`/api/assistant/models/${id}`, { method: "PATCH", body: JSON.stringify({ models: ["llama3.2", "qwen:7b"] }) }), ctx(id));
    expect(core.providers).toHaveLength(2);
    for (const p of core.providers) p.is_active = false;
    const removed = await (await provider.DELETE(request(`/api/assistant/models/${id}`, { method: "DELETE" }), ctx(id))).json();
    expect(removed.providers).toEqual([]);
    expect(core.providers).toHaveLength(0);
  });

  it("Reconix is built in: choosing it switches to the Core API's own row, never adds one", async () => {
    core.providers.push({ llm_provider_id: "5f2b7c1e-3a4d-4e5f-8a6b-7c8d9e0f1a2b", provider_type: "RECONIX", display_name: "Reconix", base_url: null, api_key_last4: null, model_name: "reconix", is_active: false, is_local: true });
    // the form finds the Core API's row (savedFor) and switches to it
    const id = "5f2b7c1e-3a4d-4e5f-8a6b-7c8d9e0f1a2b";
    const view = await (await active.PUT(request("/api/assistant/models/active", { method: "PUT", body: JSON.stringify({ providerId: id, model: "reconix" }) }))).json();
    expect(core.calls.some((c) => c.path === "/llm-providers" && c.method === "POST")).toBe(false);
    expect(view.providers[0]).toMatchObject({ preset: "reconix", models: ["reconix"] });
    expect(view.summary).toMatchObject({ configured: true, name: "reconix" });
  });

  it("maps every API provider type to the TUI's provider", async () => {
    for (const [preset, type, base] of [["openai", "OPENAI", null], ["anthropic", "ANTHROPIC", null], ["deepseek", "DEEPSEEK", null], ["custom", "OPENAI_API_COMPATIBLE", "http://127.0.0.1:1234/v1"]] as const) {
      core.calls.length = 0;
      await models.POST(request("/api/assistant/models", { method: "POST", body: JSON.stringify({ name: preset, preset, baseUrl: base ?? "https://ignored.example/v1", models: ["m-1"], apiKey: "sk-test-0123456789abcdef" }) }));
      expect(core.calls.find((c) => c.path === "/llm-providers" && c.method === "POST")!.body).toMatchObject({ provider_type: type, base_url: base });
    }
  });
});

// --- real assessments from the Core API ----------------------------------------------------

const ASSESSMENT = "7d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const ACTION = "8e2d3c4b-5f6a-4b7c-9d8e-0f1a2b3c4d5e";
const APPROVAL = "9f3e4d5c-6a7b-4c8d-8e9f-1a2b3c4d5e6f";

function seedAssessment() {
  core.assessments.push({
    row: { assessment_id: ASSESSMENT, engagement_code: "RCX-2026-0042", name: "Web app test", type: "WEB", assessment_status: "ACTIVE", created_by: "tester@host", created_at: "2026-11-05T09:30:15Z", updated_at: "2026-11-05T10:00:00Z", session_id: "s", targets: ["https://lab.example"], finding_count: 2, worst_severity: "HIGH", pending_approval_count: 1 },
    overview: { targets: ["https://lab.example"], first_started_at: "2026-11-05T09:35:00Z", last_finished_at: null, request_count: 12, plan_step_count: 2, plan_step_done_count: 1 },
    findings: [
      { code: "F-001", title: "SQL injection in search", target: "https://lab.example/search", description: "d", severity_status: "HIGH", cvss_score: "8.1", cwe_ids: ["CWE-89"], owasp_id: ["A03:2021"], cve_ids: [], impact: "i", remediation: "Use bound parameters", validation_status: "CONFIRMED", finding_status: "OPEN", tools: ["SQLMAP"] },
      { code: "F-002", title: "Missing header", target: "https://lab.example", description: "d", severity_status: "LOW", cvss_score: null, cwe_ids: [], owasp_id: [], cve_ids: [], impact: null, remediation: null, validation_status: "UNCONFIRMED", finding_status: "FALSE_POSITIVE", tools: ["NUCLEI"] },
    ],
    actions: [{ action_id: ACTION, tool: "NMAP", args: ["-sV"], target: "lab.example", purpose: "ports", risk_level: "MEDIUM", action_status: "PENDING", guardrail_report: {}, created_at: "2026-11-05T09:40:00Z", approval_id: APPROVAL, tool_runs: [] }],
    events: [{ event_type: "SCOPE_APPROVED", at: "2026-11-05T09:31:00Z", actor: "tester@host", session_id: "s", details: {} }],
  });
  core.approvals.push({ approval_id: APPROVAL, kind: "action", subject_snapshot: { tool: "NMAP", target: "lab.example", args: ["-sV"] }, subject_hash: "h", risk_level: "MEDIUM", approval_status: "PENDING", reason: null, decided_by: null, decided_at: null, action_id: ACTION });
}

/** A run like the live RCX-2026-0001: 28 findings, 25 the tools gave no rating (UNKNOWN) and 2
    informational (NONE). The API sends both; the assistant must show them, not lose the run. */
function seedUnrated() {
  const finding = (n: number, severity_status: string) => ({
    code: `F-${String(n).padStart(3, "0")}`,
    title: `Result ${n}`,
    target: "https://lab.example",
    description: "d",
    severity_status,
    cvss_score: null,
    cwe_ids: [],
    owasp_id: [],
    cve_ids: [],
    impact: null,
    remediation: null,
    validation_status: "UNCONFIRMED",
    finding_status: "OPEN",
    tools: ["NUCLEI"],
  });
  const unrated = (from: number, severity_status: string, count: number) => Array.from({ length: count }, (_, i) => finding(from + i, severity_status));
  core.assessments.push({
    row: { assessment_id: ASSESSMENT, engagement_code: "RCX-2026-0001", name: "Web app test", type: "WEB", assessment_status: "COMPLETED", created_by: "tester@host", created_at: "2026-11-12T09:30:15Z", updated_at: "2026-11-12T10:00:00Z", session_id: "s", targets: ["https://lab.example"], finding_count: 28, pending_approval_count: 0 },
    overview: { targets: ["https://lab.example"], first_started_at: "2026-11-12T09:35:00Z", last_finished_at: "2026-11-12T09:59:00Z", request_count: 12, plan_step_count: 2, plan_step_done_count: 2 },
    findings: [...unrated(1, "UNKNOWN", 25), ...unrated(26, "NONE", 2), finding(28, "HIGH")],
    actions: [],
    events: [],
  });
}

describe("the assistant's data comes from the Core API", () => {
  it("keeps a run whose findings the tools left unrated: UNKNOWN and NONE are shown, never dropped", async () => {
    seedUnrated();
    const { loadApiLibrary } = await import("@/lib/api/library");
    const library = await loadApiLibrary();
    expect(library.problems).toEqual([]); // before the fix the whole run was dropped here
    expect(library.assessments).toHaveLength(1);
    const [run] = library.assessments;
    expect(run.findings.filter((f) => f.severity === "UNKNOWN")).toHaveLength(25);
    expect(run.findings.filter((f) => f.severity === "NONE")).toHaveLength(2);
    const cards = pickCards(library.assessments, run.uid, "Show me the findings of RCX-2026-0001");
    const card = cards.find((c): c is CardOf<"findings"> => c.kind === "findings");
    expect(card).toBeDefined();
    expect(card?.total).toBe(28);
    expect(card?.counts).toEqual({ CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, UNKNOWN: 25, NONE: 2 });
    expect(card?.items.map((f) => f.severity)).toEqual(["HIGH", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"]); // worst first
    expect(buildContext(library.assessments, run.uid)?.text).toContain("findings 28 (1 high, 25 unknown, 2 none)");
  });

  it("reads each assessment as a run: id, status, findings, approvals", async () => {
    seedAssessment();
    const { loadApiLibrary } = await import("@/lib/api/library");
    const library = await loadApiLibrary();
    expect(library.problems).toEqual([]);
    const [run] = library.assessments;
    expect(run.uid).toBe("20261105-093015-7d1c_RCX-2026-0042");
    expect(run).toMatchObject({ assessment_id: "RCX-2026-0042", target: "https://lab.example", status: "Awaiting input", waiting_request_id: APPROVAL });
    expect(run.findings.map((f) => [f.id, f.severity, f.validation, f.status, f.cvss_score])).toEqual([
      ["F-001", "HIGH", "CONFIRMED", "open", 8.1],
      ["F-002", "LOW", "UNCONFIRMED", "false-positive", 0],
    ]);
    expect(run.approvals).toEqual([expect.objectContaining({ request_id: APPROVAL, action: "NMAP", target: "lab.example", risk: "MEDIUM", command: "NMAP -sV" })]);
  });

  it("the chat's cards show the API's findings, never the saved demo files", async () => {
    seedAssessment();
    await addLocalModel();
    const frames = await framesOf(await ask({ uid: null, question: "Show me the findings" }));
    const card = frames.find((f) => f.t === "card");
    expect(card && card.t === "card" && card.card.kind).toBe("findings");
    const text = JSON.stringify(frames);
    expect(text).toContain("SQL injection in search");
    expect(text).not.toContain("RCX-DEMO"); // the demo runs in sample-data stay out
  });

  it("with no assessment in the API there are no cards (and no demo data)", async () => {
    await addLocalModel();
    const frames = await framesOf(await ask({ uid: null, question: "Show me the findings" }));
    expect(JSON.stringify(frames)).not.toContain("RCX-DEMO");
  });
});
