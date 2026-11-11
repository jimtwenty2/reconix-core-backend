/* The Report view's Core API reads (lib/api/reports.ts), its rows and summary strip
   (lib/api/adapt.ts), and the file route (/api/core-reports/<id>/download): read-only, the API's
   refusals passed on as it said them, a file name kept only when it is plain. Against the fake API. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({ signed: true }));
vi.mock("@/lib/auth/guard", () => ({ requireSignedIn: async () => undefined, signedIn: async () => auth.signed }));

import { GET } from "@/app/api/core-reports/[id]/download/route";
import { overviewStats, reportRow } from "@/lib/api/adapt";
import { CoreApiError, resetSession } from "@/lib/api/client";
import { type ApiOverview, type ApiReport, listReports, readOverview } from "@/lib/api/reports";

import { ASSESSMENT_ID, type FakeApi, installFakeApi, overviewOut, REPORT_ID, reportOut } from "./fakes/core-api";

let api: FakeApi;
beforeEach(() => {
  auth.signed = true;
  resetSession();
  api = installFakeApi();
});
afterEach(() => vi.unstubAllGlobals());

const download = (id: string, format: string) => GET(new Request(`http://127.0.0.1:3100/api/core-reports/${id}/download?format=${format}`), { params: Promise.resolve({ id }) });

describe("reading reports", () => {
  it("lists an assessment's reports and reads its overview", async () => {
    expect((await listReports(ASSESSMENT_ID)).map((r) => r.version)).toEqual([2]);
    expect((await readOverview(ASSESSMENT_ID)).tool_run_count).toBe(5);
    expect(api.calls.map((c) => c.path)).toContain(`/assessments/${ASSESSMENT_ID}/reports`);
  });

  it("refuses an id that isn't a UUID before calling", async () => {
    await expect(listReports("../findings")).rejects.toBeInstanceOf(CoreApiError);
    expect(api.calls.some((c) => c.method === "GET")).toBe(false);
  });

  it("fails loudly on a report that doesn't match the contract", async () => {
    api.answers.set(`/assessments/${ASSESSMENT_ID}/reports`, [{ status: 200, body: [{ ...reportOut, report_status: "DONE" }] }]);
    await expect(listReports(ASSESSMENT_ID)).rejects.toMatchObject({ code: "BAD_RESPONSE" });
  });
});

describe("report rows", () => {
  const r = reportOut as unknown as ApiReport;
  it("offers a READY, signed-off report's files", () => {
    const row = reportRow(r);
    expect([row.locked, row.formats, row.status.label, row.review.label, row.covers]).toEqual([null, ["PDF", "DOCX", "JSON"], "Ready", "Signed off", 1]);
  });
  it("says why a report's files are locked", () => {
    expect(reportRow({ ...r, report_status: "GENERATING" }).locked).toMatch(/^Generating: /);
    expect(reportRow({ ...r, signed_off: false, review_status: "PENDING" }).locked).toMatch(/^Review pending: /);
    expect(reportRow({ ...r, signed_off: false, review_status: null }).locked).toMatch(/^Not reviewed: .*TUI/);
    expect(reportRow({ ...r, formats: [] }).locked).toBe("The Core API holds no file for this version.");
    expect(reportRow({ ...r, signed_off: false }).locked).toMatch(/^The review shows as approved, but .*sign-off/);
  });
  it("names a combined report's assessments", () => expect(reportRow({ ...r, assessment_ids: ["a", "b", "c"] }).covers).toBe(3));
});

describe("the summary strip", () => {
  const o = overviewOut as unknown as ApiOverview;
  it("counts from the overview", () => {
    const [findings, plan, runs, masked] = overviewStats(o);
    expect([findings.value, findings.note, plan.value, plan.note, runs.value, runs.note, masked.value]).toEqual(["1", "1 high · worst severity", "3/4", "75% of the plan done", "5", "2m 05s from the first tool run to the last", "2"]);
  });
  it("says unrated findings are there rather than none", () => {
    const [findings] = overviewStats({ ...o, finding_count: 2, findings_by_severity: { UNKNOWN: 1, NONE: 1 } });
    expect([findings.note, findings.badges]).toEqual(["2 findings with no severity rating", []]);
  });
});

describe("GET /api/core-reports/<id>/download", () => {
  it("needs a session", async () => {
    auth.signed = false;
    expect((await download(REPORT_ID, "PDF")).status).toBe(401);
    expect(api.calls).toEqual([]);
  });

  it("refuses an unknown format or id before calling", async () => {
    expect((await download(REPORT_ID, "pdf")).status).toBe(400);
    expect((await download("not-an-id", "PDF")).status).toBe(400);
    expect(api.calls.some((c) => c.method === "GET")).toBe(false);
  });

  it("passes the file on as a download under the API's plain name", async () => {
    const res = await download(REPORT_ID, "PDF");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/pdf");
    expect(res.headers.get("content-disposition")).toBe('attachment; filename="ENG-TEST-v2.pdf"');
    expect(await res.text()).toBe("%PDF-1.4 fake");
    expect(api.calls.at(-1)?.path).toBe(`/reports/${REPORT_ID}/download?format=PDF`);
  });

  it("falls back to a plain name when the API's isn't one", async () => {
    api.answers.set(`/reports/${REPORT_ID}/download?format=DOCX`, [
      { status: 200, body: null, raw: "PK", headers: { "Content-Type": "application/octet-stream", "Content-Disposition": 'attachment; filename="../x.docx"' } },
    ]);
    expect((await download(REPORT_ID, "DOCX")).headers.get("content-disposition")).toBe('attachment; filename="report.docx"');
  });

  it("passes a refusal on with the API's code, message and status", async () => {
    api.answers.set(`/reports/${REPORT_ID}/download?format=JSON`, [{ status: 409, body: { code: "REPORT_NOT_SIGNED_OFF", message: "A person must approve the review first.", details: {} } }]);
    const res = await download(REPORT_ID, "JSON");
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ code: "REPORT_NOT_SIGNED_OFF", message: "A person must approve the review first." });
  });

  it("names the file's type by its format, never the API's", async () => {
    api.answers.set(`/reports/${REPORT_ID}/download?format=JSON`, [{ status: 200, body: null, raw: "{}", headers: { "Content-Type": "text/html", "Content-Disposition": 'attachment; filename="r.json"' } }]);
    expect((await download(REPORT_ID, "JSON")).headers.get("content-type")).toBe("application/json");
  });

  it("refuses an empty file and one over the size cap, saving nothing", async () => {
    api.answers.set(`/reports/${REPORT_ID}/download?format=PDF`, [
      { status: 200, body: null, raw: "", headers: { "Content-Type": "application/pdf" } },
      { status: 200, body: null, raw: "x", headers: { "Content-Type": "application/pdf", "Content-Length": String(51 * 1024 * 1024) } },
    ]);
    const empty = await download(REPORT_ID, "PDF");
    expect([empty.status, (await empty.json()).code]).toEqual([502, "BAD_RESPONSE"]);
    const big = await download(REPORT_ID, "PDF");
    expect([big.status, (await big.json()).code]).toEqual([413, "TOO_LARGE"]);
  });

  it("says the API is down as a 502", async () => {
    api.down = true;
    const res = await download(REPORT_ID, "PDF");
    expect(res.status).toBe(502);
    expect((await res.json()).code).toBe("UNREACHABLE");
  });
});
