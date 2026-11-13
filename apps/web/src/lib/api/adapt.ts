/* Core API answers → the Findings view's rows. Pure: no I/O, no invented values. Translating
   happens here only: UPPERCASE ERD V3 enums stay UPPERCASE (UNKNOWN and NONE severities are
   shown), except the triage status, which becomes the view's own words (lib/data/stats.ts). */
import { findingIcon, type ListedFinding } from "@/components/dashboard/derive";
import { plural } from "@/components/dashboard/derive-shared";
import type { EventBadge } from "@/components/dashboard/overview-types";
import type { Stat } from "@/components/dashboard/stat-types";
import { evidenceTone } from "@/lib/data/adapt";
import { duration, hourMinute, shortDay } from "@/lib/data/format";
import { type FindingSeverity, isFindingSeverity, SEVERITIES } from "@/lib/data/schema";
import { type Meaning, REPORT_REVIEW, REPORT_STATUS, SEVERITY_META } from "@/lib/status";

import type { ApiAssessment, ApiFinding } from "./findings";
import type { ApiOverview, ApiReport, ReportFormat } from "./reports";

const TRIAGE: Record<string, string> = { OPEN: "open", FIXED: "fixed", FALSE_POSITIVE: "false-positive" };

/** The API's `severity_status` on the web's scale: UPPERCASE ERD V3, and anything off it (a value
    this web does not know yet) reads as UNKNOWN — the tool gave no rating — so one unexpected
    word never drops a run. The TUI's `core_api/adapt.py::severity` does the same. */
export function severityOf(value: string): FindingSeverity {
  const level = value.trim().toUpperCase();
  return isFindingSeverity(level) ? level : "UNKNOWN";
}

/** The assessment a row came from, as the "all assessments" list names it. */
export function runOf(a: Pick<ApiAssessment, "assessment_id" | "name">): NonNullable<ListedFinding["run"]> {
  const id = a.assessment_id;
  return { uid: id, label: a.name || id.slice(0, 8), href: `/?view=findings&assessment=${encodeURIComponent(id)}` };
}

/** The assessment picker's choices ("Juice Shop web · 12": its findings, false positives left out). */
export const pickerItems = (assessments: ApiAssessment[]) => assessments.map((a) => ({ id: a.assessment_id, label: `${a.name || a.assessment_id.slice(0, 8)} · ${a.finding_count}` }));

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

const when = (iso: string | null) => {
  const ms = iso ? Date.parse(iso) : NaN;
  return Number.isFinite(ms) ? `${shortDay(ms)} ${hourMinute(ms)}` : "—";
};

/** The Report view's summary strip, from GET /assessments/{id}/overview (false positives are
    already left out of its finding counts). */
export function overviewStats(o: ApiOverview): Stat[] {
  const worst = SEVERITIES.find((s) => (o.findings_by_severity[s] ?? 0) > 0) ?? null;
  const badges: EventBadge[] = worst ? [{ type: "severity", level: worst }] : [];
  const unrated = (o.findings_by_severity.UNKNOWN ?? 0) + (o.findings_by_severity.NONE ?? 0);
  const findingsNote = worst
    ? `${o.findings_by_severity[worst]} ${SEVERITY_META[worst].label.toLowerCase()} · worst severity`
    : unrated
      ? `${plural(unrated, "finding")} with no severity rating`
      : "No findings yet";
  const total = o.plan_step_count;
  const done = o.plan_step_done_count;
  return [
    { label: "Findings", icon: "findings", value: String(o.finding_count), format: "int", unit: null, badges, meter: null, note: findingsNote, link: { view: "findings", filters: {}, label: "Open the findings" } },
    {
      label: "Plan steps",
      icon: "steps",
      value: `${done}/${total}`,
      format: "none",
      unit: null,
      badges: [],
      meter: total ? { frac: done / total, over: false, label: "Plan done" } : null,
      note: total ? `${Math.round((done / total) * 100)}% of the plan done` : "No plan yet",
      link: null,
    },
    { label: "Tool runs", icon: "runs", value: String(o.tool_run_count), format: "int", unit: null, badges: [], meter: null, note: o.duration_seconds ? `${duration(o.duration_seconds)} from the first tool run to the last` : "No tool has run yet", link: null },
    { label: "Masked evidence", icon: "masked", value: String(o.masked_count), format: "int", unit: null, badges: [], meter: null, note: "Values the Core API masked before saving", link: null },
  ];
}

/** One report version as the Report view lists it, with whether (and why not) it downloads. */
export interface ReportRow {
  id: string;
  version: number;
  status: Meaning;
  review: Meaning;
  made: string; // "10 Nov 09:00 · tester@lab"
  covers: number; // assessments it covers (2 to 5: a combined report)
  formats: ReportFormat[];
  /** Why its files can't be downloaded yet, or null when they can. */
  locked: string | null;
  summary: string;
}

export function reportRow(r: ApiReport): ReportRow {
  const review = REPORT_REVIEW[r.review_status ?? "NONE"];
  const locked =
    r.report_status !== "READY"
      ? `${REPORT_STATUS[r.report_status].label}: ${REPORT_STATUS[r.report_status].hint}`
      : !r.signed_off
        ? r.review_status === "APPROVED"
          ? "The review shows as approved, but the Core API has not recorded the sign-off: check it in the TUI."
          : `${review.label}: ${review.hint}`
        : !r.formats.length
          ? "The Core API holds no file for this version."
          : null;
  return {
    id: r.report_id,
    version: r.version,
    status: REPORT_STATUS[r.report_status],
    review,
    made: `${when(r.generated_at ?? r.created_at)} · ${r.generated_by}`,
    covers: r.assessment_ids.length,
    formats: r.formats,
    locked,
    summary: r.executive_summary ?? "",
  };
}

