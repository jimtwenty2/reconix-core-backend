/* lib/api/library.ts runOf: one Core API assessment as the run the Overview reads. A finding the
   API rates NONE or UNKNOWN used to fail the run shape and drop the whole assessment from the
   Overview; now it is kept (out of the four-level severity counts). */
import { describe, expect, it } from "vitest";

import { runOf } from "@/lib/api/library";

const AT = "2026-11-11T12:39:56.274575Z";
const row = {
  assessment_id: "5cf06e1c-ad43-4df2-8626-e0778f9e4a1f",
  engagement_code: "RCX-2026-0001",
  name: "RCX-001",
  type: "web_url",
  assessment_status: "ACTIVE",
  created_by: "tester@lab",
  created_at: AT,
  updated_at: AT,
  session_id: "74d2e01c-b6b0-4825-97bd-128fe3bcb31a",
  targets: ["https://testphp.vulnweb.com/"],
  pending_approval_count: 0,
};
const overview = { targets: row.targets, first_started_at: AT, last_finished_at: null, request_count: 0, plan_step_count: 5, plan_step_done_count: 1 };
const finding = (severity_status: string) => ({
  code: `F-${severity_status}`,
  title: "A finding",
  target: row.targets[0],
  description: "",
  severity_status,
  cvss_score: null,
  cwe_ids: [],
  owasp_id: [],
  cve_ids: [],
  impact: null,
  remediation: null,
  validation_status: "UNCONFIRMED",
  finding_status: "OPEN",
  tools: ["whatweb"],
});

describe("runOf", () => {
  it("keeps an assessment whose findings are NONE or UNKNOWN", () => {
    const run = runOf(row, overview, [finding("NONE"), finding("UNKNOWN"), finding("HIGH")], [], [], [], "Completed");
    expect(run.status).toBe("Completed");
    expect(run.findings.map((f) => f.severity)).toEqual(["NONE", "UNKNOWN", "HIGH"]);
  });

  it("uses the API's own status without a live one", () => {
    expect(runOf(row, overview, [], [], [], []).status).toBe("Running");
  });
});
