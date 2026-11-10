/* Core API answers → the Findings view's rows. Pure: no I/O, no invented values. Translating
   happens here only: UPPERCASE ERD V3 enums stay UPPERCASE (UNKNOWN and NONE severities are
   shown), except the triage status, which becomes the view's own words (lib/data/stats.ts). */
import { findingIcon, type ListedFinding } from "@/components/dashboard/derive";
import { evidenceTone } from "@/lib/data/adapt";

import type { ApiAssessment, ApiFinding } from "./findings";

const TRIAGE: Record<string, string> = { OPEN: "open", FIXED: "fixed", FALSE_POSITIVE: "false-positive" };

/** The assessment a row came from, as the "all assessments" list names it. */
export function runOf(a: Pick<ApiAssessment, "assessment_id" | "name">): NonNullable<ListedFinding["run"]> {
  const id = a.assessment_id;
  return { uid: id, label: a.name || id.slice(0, 8), href: `/?view=findings&assessment=${encodeURIComponent(id)}` };
}

export function apiFindingRow(f: ApiFinding, run: ListedFinding["run"] = null): ListedFinding {
  const cvss = f.cvss_score === null ? NaN : Number(f.cvss_score);
  const score = Number.isFinite(cvss) && cvss > 0 ? cvss : null;
  const id = f.code || f.finding_id.slice(0, 8);
  const category = f.owasp_id[0] ?? "";
  const confirmed = f.validation_status === "CONFIRMED";
  const status = TRIAGE[f.finding_status] ?? f.finding_status;
  return {
    id,
    key: run ? `${run.uid}~${id}` : id,
    run,
    icon: findingIcon({ category, title: f.title }),
    title: f.title,
    severity: f.severity_status,
    target: f.target || "—",
    tool: f.tools.join(", ") || "—",
    cwe: f.cwe_ids[0] ?? "—",
    category,
    score,
    rating: score === null ? "no CVSS" : `CVSS ${score.toFixed(1)}`,
    validation: f.validation_status,
    confirmed,
    needsReview: status === "open" && !confirmed,
    falsePositive: f.finding_status === "FALSE_POSITIVE",
    status,
    description: f.description,
    impact: f.impact ?? "",
    evidence: f.evidence.flatMap((e) => {
      const text = [e.location, e.content].filter(Boolean).join("\n");
      return text ? [{ text, tone: evidenceTone(e.content ?? text) }] : [];
    }),
    remediation: (f.remediation ?? "")
      .split("\n")
      .map((r) => r.trim())
      .filter(Boolean),
    references: [...new Set([...f.cwe_ids, ...f.owasp_id, ...f.cve_ids])],
  };
}

/** Every row, named by its code (`F-001`, as links and the address show it); a code two findings
    of one assessment share (the API doesn't make codes unique) falls back to its finding_id. With
    `across` (the assessments), each row also names the assessment it came from. */
export function apiFindingRows(findings: ApiFinding[], across: ApiAssessment[] | null = null): ListedFinding[] {
  const byId = new Map((across ?? []).map((a) => [a.assessment_id, a]));
  const seen = new Map<string, number>();
  for (const f of findings) seen.set(`${f.assessment_id}~${f.code}`, (seen.get(`${f.assessment_id}~${f.code}`) ?? 0) + 1);
  return findings.map((f) => {
    const run = across ? runOf(byId.get(f.assessment_id) ?? { assessment_id: f.assessment_id, name: "" }) : null;
    const row = apiFindingRow(f, run);
    if ((seen.get(`${f.assessment_id}~${f.code}`) ?? 0) < 2) return row;
    return { ...row, key: run ? `${run.uid}~${f.finding_id}` : f.finding_id };
  });
}
