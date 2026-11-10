/* The Findings view's Core API client (lib/api/): the loopback-only address, the web session
   (opened once, renewed once after a 401), the API's refusals shown as it said them, answers
   checked against the contract, and FindingOut → the view's rows. Against the fake API. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth/guard", () => ({ requireSignedIn: async () => undefined }));

import { apiFindingRow, runOf } from "@/lib/api/adapt";
import { baseUrl, CoreApiError, NOT_RUNNING, resetSession } from "@/lib/api/client";
import { type ApiFinding, listAssessments, listFindings } from "@/lib/api/findings";

import { ASSESSMENT_ID, assessmentRow, FAKE_TOKEN, type FakeApi, findings, installFakeApi } from "./fakes/core-api";

let api: FakeApi;
beforeEach(() => {
  resetSession();
  api = installFakeApi();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const refusal = async (p: Promise<unknown>) => {
  const e = await p.then(() => null, (err: unknown) => err);
  expect(e).toBeInstanceOf(CoreApiError);
  return e as CoreApiError;
};

describe("baseUrl", () => {
  it("defaults to the loopback API", () => expect(baseUrl()).toBe("http://127.0.0.1:8000"));
  it.each(["http://10.0.0.5:8000", "http://example.com", "ftp://127.0.0.1", "http://127.0.0.1:8000/x", "http://u:p@127.0.0.1:8000"])("refuses %s", (url) => {
    vi.stubEnv("RECONIX_CORE_API", url);
    expect(() => baseUrl()).toThrow(CoreApiError);
  });
});

describe("the web session", () => {
  it("opens one web session and sends its token on every call", async () => {
    await listAssessments();
    await listFindings(ASSESSMENT_ID);
    const opens = api.calls.filter((c) => c.path === "/sessions");
    expect(opens).toEqual([{ method: "POST", path: "/sessions", auth: null, body: { interface: "web" } }]);
    expect(api.calls.filter((c) => c.method === "GET").every((c) => c.auth === `Bearer ${FAKE_TOKEN}`)).toBe(true);
  });

  it("opens a new session once after a 401, then shows a second 401", async () => {
    const no = { status: 401, body: { code: "INVALID_TOKEN", message: "The session token is not valid.", details: {} } };
    api.answers.set("/assessments", [no]);
    await expect(listAssessments()).resolves.toEqual([assessmentRow].map(({ assessment_id, name, targets, assessment_status, finding_count, created_at }) => ({ assessment_id, name, targets, assessment_status, finding_count, created_at })));
    expect(api.calls.filter((c) => c.path === "/sessions")).toHaveLength(2);

    api.answers.set("/assessments", [no, no]);
    const e = await refusal(listAssessments());
    expect([e.code, e.status]).toEqual(["INVALID_TOKEN", 401]);
  });

  it("opens one session when two calls fail with 401 together", async () => {
    await listAssessments();
    const no = { status: 401, body: { code: "INVALID_TOKEN", message: "The session token is not valid.", details: {} } };
    api.answers.set("/assessments", [no, no]);
    await Promise.all([listAssessments(), listAssessments()]);
    expect(api.calls.filter((c) => c.path === "/sessions")).toHaveLength(2);
  });

  it("says the API is slow, not down, when it doesn't answer in time", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new DOMException("The operation timed out.", "TimeoutError");
    });
    expect((await refusal(listAssessments())).code).toBe("TIMEOUT");
  });

  it("turns a body that fails mid-read into a CoreApiError", async () => {
    vi.stubGlobal("fetch", async () => ({ ok: true, status: 200, text: async () => { throw new DOMException("The operation timed out.", "TimeoutError"); } }));
    expect((await refusal(listAssessments())).code).toBe("TIMEOUT");
  });
});

describe("refusals and failures", () => {
  it("says the API is not running when it can't be reached", async () => {
    api.down = true;
    const e = await refusal(listFindings(null));
    expect([e.code, e.message]).toEqual(["UNREACHABLE", NOT_RUNNING]);
  });

  it("passes the API's own code and message through", async () => {
    api.answers.set("/findings", [{ status: 429, body: { code: "RATE_LIMITED", message: "Too many requests.", details: {} } }]);
    const e = await refusal(listFindings(null));
    expect([e.code, e.message, e.status]).toEqual(["RATE_LIMITED", "Too many requests.", 429]);
  });

  it("fails loudly on an answer that doesn't match the contract", async () => {
    api.answers.set("/findings", [{ status: 200, body: [{ title: "half a finding" }] }]);
    expect((await refusal(listFindings(null))).code).toBe("BAD_RESPONSE");
  });

  it("refuses an id that isn't a UUID before calling", async () => {
    expect((await refusal(listFindings("../sessions"))).code).toBe("BAD_REQUEST");
    expect(api.calls.some((c) => c.path.startsWith("/findings"))).toBe(false);
  });

  it("asks for one assessment's findings by id", async () => {
    await listFindings(ASSESSMENT_ID);
    expect(api.calls.at(-1)?.path).toBe(`/findings?assessment_id=${ASSESSMENT_ID}`);
  });
});

describe("apiFindingRow", () => {
  const [sqli, unrated] = findings as unknown as ApiFinding[];

  it("maps a finding into the view's terms", () => {
    const row = apiFindingRow(sqli);
    expect(row).toMatchObject({
      id: "F-001",
      key: "F-001",
      run: null,
      severity: "HIGH",
      score: 8.6,
      rating: "CVSS 8.6",
      cwe: "CWE-89",
      tool: "sqlmap",
      validation: "CONFIRMED",
      confirmed: true,
      needsReview: false,
      falsePositive: false,
      status: "open",
      remediation: ["Use bound parameters.", "Validate the input."],
      references: ["CWE-89", "A03:2021"],
      icon: "code",
    });
    expect(row.evidence).toEqual([{ text: "q\nGET /rest/products/search?q='", tone: "request" }]);
  });

  it("keeps UNKNOWN severities and marks false positives, inventing nothing", () => {
    const row = apiFindingRow(unrated);
    expect(row).toMatchObject({ severity: "UNKNOWN", score: null, rating: "no CVSS", cwe: "—", category: "", impact: "", falsePositive: true, needsReview: false, status: "false-positive", evidence: [], remediation: [] });
  });

  it("names the assessment and links to its own list when the list spans several", () => {
    const row = apiFindingRow(sqli, runOf(assessmentRow));
    expect(row.key).toBe(`${ASSESSMENT_ID}~F-001`);
    expect(row.run).toEqual({ uid: ASSESSMENT_ID, label: "Juice Shop web", href: `/?view=findings&assessment=${ASSESSMENT_ID}` });
  });
});
