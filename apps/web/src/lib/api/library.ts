/* The AI Assistant's data from the Core API, in the run shape its cards, prompts and scope
   picker read (lib/data/schema.ts `Assessment`), so they show the API's real assessments and
   never the saved demo files. Per assessment: GET /assessments/{id}/overview, /findings,
   /actions and /timeline; the approvals once (PENDING, APPROVED, REJECTED). Only what the API
   records is filled in; the rest stays empty. Server only. */
import "server-only";

import { ZodError } from "zod";

import { type Assessment, AssessmentSchema, STATUSES } from "../data/schema";
import type { Library } from "../data/store";
import { severityOf } from "./adapt";
import { liveStatus, newestPlanRun, typeLabel } from "./assessments";
import { CoreError, coreJson } from "./core";
import { asMain } from "./sessions";

const MAX_ASSESSMENTS = 50;

type Row = {
  assessment_id: string;
  engagement_code: string;
  name: string;
  type: string;
  assessment_status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  session_id: string;
  targets: string[];
  pending_approval_count: number;
};
type Overview = {
  targets: string[];
  first_started_at: string | null;
  last_finished_at: string | null;
  request_count: number;
  plan_step_count: number;
  plan_step_done_count: number;
  time_window_seconds?: number | null;
};
type CoreFinding = {
  code: string;
  title: string;
  target: string;
  description: string;
  severity_status: string;
  cvss_score: number | string | null;
  cwe_ids: string[];
  owasp_id: string[];
  cve_ids: string[];
  impact: string | null;
  remediation: string | null;
  validation_status: string;
  finding_status: string;
  tools: string[];
  triage_note?: string;
};
type CoreAction = {
  action_id: string;
  tool: string;
  args: string[];
  target: string;
  purpose: string;
  risk_level: string | null;
  action_status: string;
  guardrail_report: Record<string, unknown>;
  created_at: string;
  approval_id: string | null;
  tool_runs: { request_count: number }[];
};
type CoreApproval = {
  approval_id: string;
  kind: string;
  subject_snapshot: Record<string, unknown>;
  subject_hash: string;
  risk_level: string | null;
  approval_status: string;
  reason: string | null;
  decided_by: string | null;
  decided_at: string | null;
  action_id: string | null;
};
type CoreEvent = { event_type: string; at: string; actor: string; details: Record<string, unknown> };
export type CoreMessage = { message_id: string; sequence_no: number; role: string; content_masked: string; created_at: string; session_id: string };

/** A run id the dashboard's links accept: "<yyyymmdd-hhmmss>-<4 hex>_<code>". */
export function uidOf(row: Pick<Row, "assessment_id" | "created_at" | "engagement_code">): string {
  const t = new Date(row.created_at);
  const two = (n: number) => String(n).padStart(2, "0");
  const stamp = Number.isNaN(t.getTime())
    ? "00000000-000000"
    : `${t.getUTCFullYear()}${two(t.getUTCMonth() + 1)}${two(t.getUTCDate())}-${two(t.getUTCHours())}${two(t.getUTCMinutes())}${two(t.getUTCSeconds())}`;
  const code = row.engagement_code.replace(/[^A-Za-z0-9-]/g, "-").slice(0, 64) || "assessment";
  return `${stamp}-${row.assessment_id.replace(/-/g, "").slice(0, 4).toLowerCase()}_${code}`;
}

/** The API's status as the run's: an ACTIVE one with an approval waiting is "Awaiting input". */
export function statusOf(status: string, waiting: boolean): (typeof STATUSES)[number] {
  if (status === "COMPLETED") return "Completed";
  if (status === "CANCELLED") return "Stopped";
  if (status === "DRAFT") return "New";
  return waiting ? "Awaiting input" : "Running";
}

const TRIAGE: Record<string, string> = { OPEN: "open", FALSE_POSITIVE: "false-positive", FIXED: "fixed" };
const STEP: Record<string, "pending" | "active" | "done"> = { COMPLETED: "done", FAILED: "done", APPROVED: "active", PENDING: "pending" };

const words = (eventType: string) => eventType.toLowerCase().replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
const detail = (d: Record<string, unknown>, key: string) => (typeof d[key] === "string" ? (d[key] as string) : "");

/** A timeline event as an activity line: its author and words decide its kind (adapt.ts). */
function entryOf(e: CoreEvent, seq: number): Assessment["timeline"][number] {
  const t = e.event_type;
  const what = [detail(e.details, "tool"), detail(e.details, "target")].filter(Boolean).join(" ");
  const text = what ? `${words(t)}: ${what}` : words(t);
  const [who, tone] = /^TOOL_RUN/.test(t)
    ? ["TOOL", ""]
    : /BLOCKED/.test(t)
      ? ["POLICY", "block"]
      : /^APPROVAL/.test(t)
        ? ["POLICY", "warn"]
        : t === "SCOPE_APPROVED"
          ? ["USER", ""]
          : /^FINDING/.test(t)
            ? ["AI", ""]
            : ["SYSTEM", ""];
  return { seq, at: e.at, type: "activity", who, kind: t, text: t === "SCOPE_APPROVED" ? "Scope approved" : /^FINDING/.test(t) ? `Finding: ${what || words(t)}` : text, tone, rows: [] };
}

/** The run shape's severities (lib/data/schema.ts SAVED_SEVERITIES): the four levels as they
 *  are; the API's NONE and UNKNOWN have no level there, so they become INFO, which the
 *  Overview and Run log leave out of their severity counts (schema.ts withoutInfo). The
 *  Findings and Assessments views read the API directly and still show them. */
function findingOf(f: CoreFinding) {
  const score = typeof f.cvss_score === "string" ? Number(f.cvss_score) : (f.cvss_score ?? 0);
  return {
    id: f.code,
    severity: severityOf(f.severity_status),
    title: f.title,
    path: f.target,
    validation: f.validation_status,
    description: f.description ?? "",
    affected_url: f.target,
    impact: f.impact ?? "",
    remediation: f.remediation ?? "",
    tool: f.tools ? f.tools.join(", ") : "",
    references: [...(f.cwe_ids ?? []), ...(f.owasp_id ?? []), ...(f.cve_ids ?? [])],
    evidence: [],
    cvss_score: Number.isFinite(score) ? score : 0,
    cwe: f.cwe_ids ?? [],
    owasp: f.owasp_id ?? [],
    cve: f.cve_ids ?? [],
    status: TRIAGE[f.finding_status] ?? "open",
  };
}

const snap = (a: CoreApproval, key: string) => {
  const v = a.subject_snapshot[key];
  return Array.isArray(v) ? v.join(" ") : typeof v === "string" ? v : "";
};

/** One API assessment as a run. `live`: the status its newest plan run gives
 *  (assessments.ts liveStatus, the Assessments view's too); without it, the API's own status. */
export function runOf(
  row: Row,
  overview: Overview,
  findings: CoreFinding[],
  actions: CoreAction[],
  approvals: CoreApproval[],
  events: CoreEvent[],
  messagesOrLive: CoreMessage[] | (typeof STATUSES)[number] | null = [],
  liveStatusParam: (typeof STATUSES)[number] | null = null,
): Assessment {
  let messages: CoreMessage[] = [];
  let live: (typeof STATUSES)[number] | null = null;
  if (typeof messagesOrLive === "string") {
    live = messagesOrLive;
  } else if (Array.isArray(messagesOrLive)) {
    messages = messagesOrLive;
    live = liveStatusParam;
  }

  const ids = new Set(actions.map((a) => a.action_id));
  const mine = approvals.filter((a) => a.kind === "action" && a.action_id && ids.has(a.action_id));
  const pending = mine.filter((a) => a.approval_status === "PENDING");
  const status = live ?? statusOf(row.assessment_status, pending.length > 0);
  const target = overview.targets[0] ?? row.targets[0] ?? "";
  const blocked = actions.filter((a) => a.action_status === "BLOCKED");

  const chatEntries: Assessment["timeline"] = messages.map((m) => ({
    seq: 0,
    at: m.created_at,
    type: "chat" as const,
    who: m.role === "user" ? "you" : "reconix",
    kind: "text",
    text: m.content_masked,
    tone: "default",
    rows: [],
  }));
  const activityEntries = events.map(entryOf);
  const allTimeline = [...chatEntries, ...activityEntries]
    .sort((a, b) => {
      const ta = a.at ? new Date(a.at).getTime() : 0;
      const tb = b.at ? new Date(b.at).getTime() : 0;
      return ta - tb;
    })
    .map((e, idx) => ({ ...e, seq: idx + 1 }));

  const saved = {
    schema: "reconix.assessment/v1" as const,
    uid: uidOf(row),
    session: row.session_id,
    label: row.engagement_code,
    assessment_id: row.engagement_code,
    core_id: row.assessment_id,
    target,
    target_url: target,
    target_kind: row.type,
    template: { id: row.type, name: typeLabel(row.type), confirmed: true },
    operator: row.created_by,
    created_at: row.created_at,
    saved_at: row.updated_at,
    status,
    waiting_gate: pending.length ? "approval" : "",
    waiting_request_id: pending[0]?.approval_id ?? "",
    waiting_for: pending.length ? "an approval" : "",
    stopped_reason: "",
    run: {
      phase: "",
      started_at: overview.first_started_at,
      finished_at: overview.last_finished_at,
      completed: row.assessment_status === "COMPLETED",
      requests: overview.request_count,
      progress: overview.plan_step_count ? { plan: Math.round((100 * overview.plan_step_done_count) / overview.plan_step_count) } : {},
      report_path: "",
    },
    login: { kind: "", provided: false },
    plan: actions.map((a) => ({ key: a.action_id, label: [a.tool, a.target].filter(Boolean).join(" "), status: STEP[a.action_status] ?? "pending" })),
    scope: target
      ? {
          kind: row.type,
          target_url: target,
          assessment_type: row.type,
          status: row.assessment_status === "DRAFT" ? "DRAFT" : "APPROVED",
          allowed_actions: [],
          allowed_methods: [],
          excluded_paths: [],
          allowed_ports: [],
          time_limit_minutes: overview.time_window_seconds ? Math.round(overview.time_window_seconds / 60) : 0,
          tools: [],
        }
      : null,
    verdicts: [
      ...actions.filter((a) => a.action_status !== "BLOCKED").map((a) => ({ method: a.tool, path: a.target, allowed: true, reason: "", at: a.created_at })),
      ...blocked.map((a) => ({ method: a.tool, path: a.target, allowed: false, reason: String((a.guardrail_report as { reason?: unknown }).reason ?? "Blocked by the safety checks"), at: a.created_at })),
    ],
    approvals: mine.map((a) => ({
      request_id: a.approval_id,
      risk: a.risk_level ?? "",
      action: snap(a, "tool"),
      target: snap(a, "target"),
      method: "",
      path: snap(a, "target"),
      purpose: snap(a, "purpose"),
      impact: "",
      command: [snap(a, "tool"), snap(a, "args")].filter(Boolean).join(" "),
      command_hash: a.subject_hash,
    })),
    decisions: mine
      .filter((a) => a.approval_status === "APPROVED" || a.approval_status === "REJECTED")
      .map((a) => ({ request_id: a.approval_id, decision: a.approval_status as "APPROVED" | "REJECTED", operator: a.decided_by ?? "", reason: a.reason ?? "", command_hash: a.subject_hash, at: a.decided_at })),
    findings: findings.map(findingOf),
    timeline: allTimeline,
    requests: [],
  };
  return AssessmentSchema.parse(saved);
}

/** An ACTIVE assessment's status from its newest plan run (GET /sessions/{id}/agent-runs), as
 *  the Assessments view shows it. null for one that isn't ACTIVE, or when its session's runs
 *  can't be read (then runOf keeps the API's own status, so the run is not dropped for it). */
async function liveOf(row: Row, get: <T>(path: string) => Promise<T>): Promise<(typeof STATUSES)[number] | null> {
  if (row.assessment_status !== "ACTIVE") return null;
  try {
    return liveStatus(row, newestPlanRun(await get<unknown>(`/sessions/${row.session_id}/agent-runs`), row.assessment_id));
  } catch {
    return null;
  }
}

/** Why one assessment could not be shown: the API's refusal as it said it, or which of its
 *  fields didn't fit the run shape (names only, never a value). */
function problemOf(error: unknown): string {
  if (error instanceof CoreError) return `The Core API refused a call: ${error.message} (${error.code}).`;
  if (error instanceof ZodError) {
    const fields = [...new Set(error.issues.map((i) => i.path.join(".")))].slice(0, 5).join(", ");
    return `Its data doesn't fit the dashboard (${fields || "unknown field"}).`;
  }
  return "The Core API could not give all of it.";
}

/** Every assessment the Core API has (newest first, at most MAX_ASSESSMENTS), as runs. */
export async function loadApiLibrary(): Promise<Library> {
  const get = <T>(path: string) => asMain((token) => coreJson<T>(path, { token }));
  const rows = (await get<Row[]>("/assessments")).slice(0, MAX_ASSESSMENTS);
  const approvals = (await Promise.all(["PENDING", "APPROVED", "REJECTED"].map((s) => get<CoreApproval[]>(`/approvals?status=${s}`).catch(() => [])))).flat();
  const problems: Library["problems"] = [];
  const runs = await Promise.all(
    rows.map(async (row) => {
      const id = row.assessment_id;
      try {
        const [overview, findings, actions, timeline, messages, live] = await Promise.all([
          get<Overview>(`/assessments/${id}/overview`),
          get<CoreFinding[]>(`/findings?assessment_id=${id}`),
          get<CoreAction[]>(`/assessments/${id}/actions`),
          get<{ events: CoreEvent[] }>(`/assessments/${id}/timeline`),
          get<CoreMessage[]>(`/sessions/${row.session_id}/messages`).catch(() => []),
          liveOf(row, get),
        ]);
        return runOf(row, overview, findings, actions, approvals, timeline.events, messages, live);
      } catch (error) {
        problems.push({ file: row.engagement_code, reason: problemOf(error) });
        return null;
      }
    }),
  );
  return { dir: "Core API", readAt: Date.now(), assessments: runs.filter((r): r is Assessment => r !== null), problems };
}
