/* The Core API's assessments and findings, read for the Findings view (server only).

   Each answer is checked against the fields this view reads (docs/openapi.json AssessmentRowOut
   and FindingOut); one that doesn't match fails loudly as BAD_RESPONSE rather than showing a
   half-read list. shortcut: hand-written subset of the contract until `gen-api-types`
   (openapi-typescript) is set up; switch to the generated types then. */
import "server-only";

import { cache } from "react";
import { z } from "zod";

import { requireSignedIn } from "../auth/guard";
import { apiGet, CoreApiError } from "./client";

const str = z.string();
const opt = z.string().nullable();

export const SEVERITY_STATUS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"] as const;

const AssessmentRow = z.object({
  assessment_id: str,
  name: str,
  targets: z.array(str),
  assessment_status: str,
  finding_count: z.number(),
  created_at: str,
});
export type ApiAssessment = z.infer<typeof AssessmentRow>;

const Evidence = z.object({ kind: str, content: opt, location: opt });

const FindingOut = z.object({
  finding_id: str,
  assessment_id: str,
  code: str,
  title: str,
  target: str,
  description: str,
  severity_status: z.enum(SEVERITY_STATUS),
  cvss_score: opt,
  cwe_ids: z.array(str),
  owasp_id: z.array(str),
  cve_ids: z.array(str),
  impact: opt,
  remediation: opt,
  validation_status: str,
  finding_status: str,
  tools: z.array(str),
  evidence: z.array(Evidence),
});
export type ApiFinding = z.infer<typeof FindingOut>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isAssessmentId = (value: unknown): value is string => typeof value === "string" && UUID.test(value);

export function parse<T>(schema: z.ZodType<T>, value: unknown, what: string): T {
  const r = schema.safeParse(value);
  if (!r.success) throw new CoreApiError("BAD_RESPONSE", `The Core API's ${what} don't match docs/openapi.json.`);
  return r.data;
}

/** GET /assessments: every assessment the API knows, as the API orders them. */
export const listAssessments = cache(async (): Promise<ApiAssessment[]> => {
  await requireSignedIn(); // a second lock behind src/proxy.ts, as lib/data/store.ts
  return parse(z.array(AssessmentRow), await apiGet("/assessments"), "assessments");
});

/** GET /findings, for one assessment or (null) every one. */
export const listFindings = cache(async (assessmentId: string | null): Promise<ApiFinding[]> => {
  await requireSignedIn();
  if (assessmentId !== null && !isAssessmentId(assessmentId)) throw new CoreApiError("BAD_REQUEST", "Not an assessment id.");
  const query = assessmentId ? `?assessment_id=${encodeURIComponent(assessmentId)}` : "";
  return parse(z.array(FindingOut), await apiGet(`/findings${query}`), "findings");
});
