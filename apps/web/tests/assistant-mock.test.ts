/* The offline mock model (reconix-mock-1): its answers match the TUI's, they use the chosen run's
   saved data, and choosing it never sends a request anywhere. */
import { readFileSync } from "node:fs";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { checkModel } from "@/lib/assistant/config";
import { factsOf, intentOf, isMockAddress, MOCK_BASE_URL, MOCK_MODEL, mockFactsFor, mockReply, mockStream } from "@/lib/assistant/models/mock";
import { presetOf, PRESETS } from "@/lib/assistant/models/presets";
import { fetchModels, testConnection } from "@/lib/assistant/models/remote";
import { assessmentView } from "@/lib/data/adapt";

import { sampleAssessments } from "./fixtures";

const TUI_REPLIES = path.join(__dirname, "..", "..", "tui", "reconix", "llm", "mock_replies.json");
const WEB_REPLIES = path.join(__dirname, "..", "src", "lib", "assistant", "models", "mock-replies.json");

const FACTS = {
  target: "10.0.0.0/24",
  scope: "Network, approved and locked; ports 22 and 443",
  step: "The run waits for you.",
  findings: [
    { id: "001", severity: "MEDIUM", title: "Old TLS", impact: "Weak crypto.", remediation: "Turn off TLS 1.0.", status: "open" },
    { id: "002", severity: "HIGH", title: "Console exposed", impact: "Takeover.", remediation: "Restrict it.", status: "open" },
  ],
};

afterEach(() => vi.restoreAllMocks());

describe("the mock model's answers", () => {
  it("reads the same prepared answers as the TUI (run scripts/sync-mock-replies.mjs)", () => {
    expect(readFileSync(WEB_REPLIES, "utf8")).toBe(readFileSync(TUI_REPLIES, "utf8"));
  });

  it.each([
    ["who are you?", "identity"],
    ["what can you do?", "capabilities"],
    ["what is in scope?", "scope"],
    ["summarize the findings", "findings"],
    ["explain finding 001", "finding"],
    ["what is the most serious finding?", "top"],
    ["what is the token?", "secret"],
    ["approve the waiting step", "action"],
    ["tell me a joke", "fallback"],
  ])("%s → %s", (question, intent) => {
    expect(intentOf(question).id).toBe(intent);
  });

  it("fills its answers from the facts", () => {
    expect(mockReply("who are you?")).toContain("mock model (reconix-mock-1)");
    expect(mockReply("summarize the findings", FACTS)).toMatch(/^2 findings \(1 HIGH, 1 MEDIUM\)/);
    expect(mockReply("explain finding 2", FACTS)).toContain("Finding 002 is HIGH: Console exposed");
    expect(mockReply("most serious finding?", FACTS)).toContain("002 HIGH Console exposed");
    expect(mockReply("what is in scope?", FACTS)).toContain("ports 22 and 443");
    expect(mockReply("summarize the findings", {})).toMatch(/^No findings yet/);
  });

  it("takes a saved run's facts, finding ids without their F- prefix", () => {
    const run = sampleAssessments().find((a) => a.findings.length > 0)!;
    const facts = factsOf(assessmentView(run));
    expect(facts.target).toBeTruthy();
    expect(facts.findings!.length).toBeGreaterThan(0);
    expect(facts.findings!.every((f) => !f.id.startsWith("F-"))).toBe(true);
    expect(mockReply("summarize the findings", facts)).toMatch(/^\d+ findings? \(/);
    expect(factsOf(null).step).toContain("No assessment is saved yet");
    expect(factsOf(assessmentView(run), false).step).toContain("This is the newest run");
  });

  it("streams the whole answer", async () => {
    const text = mockReply("who are you?");
    const reader = mockStream(text).getReader();
    const decoder = new TextDecoder();
    let out = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      out += decoder.decode(value);
    }
    expect(out).toBe(text);
  });
});

describe("the mock preset", () => {
  it("is listed, local, and passes the model rules", () => {
    const preset = presetOf("mock");
    expect(PRESETS.some((p) => p.id === "mock")).toBe(true);
    expect(preset.kind).toBe("local");
    expect(isMockAddress(preset.baseUrl)).toBe(true);
    const checked = checkModel({ baseUrl: MOCK_BASE_URL, model: MOCK_MODEL, apiKey: "sk-mock-0000-1234" });
    expect(checked.ok && checked.config.local).toBe(true);
  });

  it("tests and lists its model without any network request", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("no network in the mock"));
    const config = { baseUrl: MOCK_BASE_URL, model: MOCK_MODEL, apiKey: null, local: true };
    await expect(testConnection(config)).resolves.toMatchObject({ ok: true });
    await expect(fetchModels({ ...config, model: "" })).resolves.toEqual({ ok: true, models: [MOCK_MODEL] });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("the mock preset's address is fixed", () => {
  it("fits only its own address, and its URL field is hidden", async () => {
    const { fitsPreset } = await import("@/lib/assistant/models/presets");
    const { showsUrl } = await import("@/components/assistant/model-picker-rules");
    const preset = presetOf("mock");
    expect(fitsPreset(preset, MOCK_BASE_URL)).toBe(true);
    expect(fitsPreset(preset, `${MOCK_BASE_URL}/`)).toBe(true);
    expect(fitsPreset(preset, "https://llm.example.net/v1")).toBe(false);
    // and no other preset passes for it at its address (the picker shows such a one as Custom)
    for (const other of ["ollama", "custom", "lmstudio"]) expect(fitsPreset(presetOf(other), MOCK_BASE_URL)).toBe(false);
    expect(showsUrl(preset)).toBe(false);
  });

  it("shows statuses as the data model writes them, and picks the newest run when none is chosen", () => {
    const views = sampleAssessments().map(assessmentView);
    const facts = mockFactsFor(views, null);
    expect(facts.step).toContain("This is the newest run");
    for (const f of facts.findings ?? []) expect(f.status).toMatch(/^[A-Z_]+$/);
  });
});
