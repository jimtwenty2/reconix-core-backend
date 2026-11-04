/* The offline mock model (reconix-mock-1): prepared answers, filled with the chosen run's own
   saved data, for testing without a model or a network. A port of the TUI's
   reconix/llm/mock.py reading the same answers (mock-replies.json, copied from the TUI by
   scripts/sync-mock-replies.mjs; a test checks the copy). It is chosen in the model picker as the
   "Reconix mock (offline)" preset, whose address is MOCK_BASE_URL: the server answers it here and
   never sends a request there (llm.ts, remote.ts). Pure: browser and server. */
import type { AssessmentView } from "../../data/view-types";
import { redact } from "../redact";
import replies from "./mock-replies.json";

export const MOCK_MODEL = "reconix-mock-1";
/** The mock preset's address: a reserved loopback path nothing listens on, never called. */
export const MOCK_BASE_URL = "http://127.0.0.1/reconix-mock/v1";

export interface MockFinding {
  id: string; // "001"
  severity: string;
  title: string;
  impact: string;
  remediation: string;
  status: string;
}

export interface MockFacts {
  target?: string;
  scope?: string;
  step?: string;
  plan?: string;
  findings?: MockFinding[];
}

interface Intent {
  id: string;
  patterns: RegExp[];
  reply: string;
  needs?: string;
  empty?: string;
  missing?: string;
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];
const ABOUT = /^About [^:\n]{1,80}:\s*/;
const INTENTS: Intent[] = replies.intents.map((item) => ({ ...item, patterns: item.patterns.map((p) => new RegExp(p, "i")) }));

/** Whether a model's address is the mock's (then nothing is fetched). */
export function isMockAddress(baseUrl: string): boolean {
  return baseUrl.replace(/\/+$/, "") === MOCK_BASE_URL;
}

/** The intent that answers `question` ("fallback" when none), and a captured value. */
export function intentOf(question: string): { id: string; captured: string | null } {
  const text = question.replace(ABOUT, "").trim();
  for (const intent of INTENTS) {
    for (const pattern of intent.patterns) {
      const found = pattern.exec(text);
      if (found) return { id: intent.id, captured: found[1] ?? null };
    }
  }
  return { id: "fallback", captured: null };
}

const rank = (f: MockFinding) => {
  const at = SEVERITY_ORDER.indexOf(f.severity.toUpperCase());
  return at < 0 ? SEVERITY_ORDER.length : at;
};

function count(findings: MockFinding[]): string {
  const by = new Map<string, number>();
  for (const f of findings) by.set(f.severity.toUpperCase(), (by.get(f.severity.toUpperCase()) ?? 0) + 1);
  const parts = SEVERITY_ORDER.filter((s) => by.has(s)).map((s) => `${by.get(s)} ${s}`);
  return `${findings.length} ${findings.length === 1 ? "finding" : "findings"} (${parts.join(", ")})`;
}

function values(facts: MockFacts): Record<string, string> {
  const findings = facts.findings ?? [];
  const out: Record<string, string> = {
    target: facts.target ?? "",
    scope: facts.scope ?? "",
    step: facts.step || "Type a target to start an assessment.",
    plan: facts.plan ?? "",
    finding: findings.length ? "yes" : "",
    findings: findings.length ? "yes" : "",
  };
  if (findings.length) {
    const top = [...findings].sort((a, b) => rank(a) - rank(b))[0];
    out.top = `${top.id} ${top.severity} ${top.title}`;
    out.top_id = top.id;
    out.count = count(findings);
    out.list = findings.map((f) => `${f.id} ${f.severity} ${f.title}`).join("; ");
    out.ids = findings.map((f) => f.id).join(", ");
  }
  return out;
}

const fill = (template: string, v: Record<string, string>) => template.replace(/\{(\w+)\}/g, (_, name: string) => v[name] ?? "").trim();

/** The mock's answer to `question`, filled in from `facts`. */
export function mockReply(question: string, facts: MockFacts = {}): string {
  const { id, captured } = intentOf(question);
  if (id === "fallback") return replies.fallback;
  const intent = INTENTS.find((i) => i.id === id)!;
  const v = values(facts);
  if (intent.needs === "finding") {
    const findings = facts.findings ?? [];
    if (!findings.length) return fill(intent.empty ?? "", v);
    const wanted = (captured ?? "").padStart(3, "0");
    const match = findings.find((f) => f.id.padStart(3, "0") === wanted);
    if (!match) return fill(intent.missing ?? "", { ...v, id: wanted });
    return fill(intent.reply, { ...v, ...match });
  }
  if (intent.needs === "plan_step") return planStepReply(intent, captured ?? "", v);
  if (intent.needs && !v[intent.needs]) return fill(intent.empty ?? "", v);
  return fill(intent.reply, v);
}

/** One row of the plan ("what does step 2 do?"), not the whole plan. */
function planStepReply(intent: Intent, wanted: string, v: Record<string, string>): string {
  const rows = v.plan
    .split(";")
    .map((row) => row.trim())
    .filter(Boolean);
  if (!rows.length) return fill(intent.empty ?? "", v);
  const want = wanted.toLowerCase();
  for (const row of rows) {
    const at = row.indexOf(". ");
    if (at > 0 && row.slice(0, at).toLowerCase() === want) {
      return fill(intent.reply, { ...v, row: `${row.slice(0, at)}: ${row.slice(at + 2)}` });
    }
  }
  return fill(intent.missing ?? "", { ...v, id: want });
}

/** The facts of one saved run (null: nothing saved yet). `picked`: the operator chose this run;
    otherwise it is the newest one, and the step says so. */
export function factsOf(view: AssessmentView | null, picked = true): MockFacts {
  if (!view) return { step: "No assessment is saved yet: run one in the TUI first." };
  // saved copies are masked already; masked again here, as every other path into a reply is
  const m = (value: unknown) => redact(String(value ?? ""));
  const s = view.scope;
  const scope = s
    ? [
        `${view.template}, ${s.approved ? "APPROVED and locked" : upper(s.status)}`,
        s.ports.length ? `ports ${s.ports.join(", ")}` : s.methods.length ? `methods ${s.methods.join(", ")}` : "",
        s.exclude.length ? `never touches ${s.exclude.join(", ")}` : "",
        s.tools.length ? `tools ${s.tools.join(", ")}` : "",
        s.windowMinutes ? `time limit ${s.windowMinutes} min` : "",
      ]
        .filter(Boolean)
        .join("; ")
    : "";
  const about = picked ? "" : ` (This is the newest run, ${view.id}; pick another in the top bar.)`;
  const step = (view.gate ? `The run waits for you: ${view.gate.text}. Decide in the TUI.` : runState(view.status)) + about;
  return {
    target: m(view.target),
    scope: m(scope),
    step: m(step),
    plan: m(view.phases.map((p, i) => `${i + 1}. ${p.label} [${upper(p.status)}]`).join("; ")),
    findings: view.findings
      .filter((f) => !f.falsePositive)
      .map((f) => ({
        id: f.id.replace(/^F-/i, ""),
        severity: f.severity,
        title: m(f.title),
        impact: m(f.impact),
        remediation: m(Array.isArray(f.remediation) ? f.remediation.join(" ") : f.remediation),
        status: upper(f.status),
      })),
  };
}

/** Where a run that waits for nothing stands: only a run still going has more to come. */
function runState(status: unknown): string {
  const word = upper(status);
  if (["COMPLETED", "STOPPED", "INTERRUPTED", "FAILED", "CANCELLED"].includes(word)) {
    return `The run is ${word}: nothing is left to decide. Start a new one in the TUI.`;
  }
  return `The run is ${word}. Any decision it needs is made in the TUI.`;
}

/** A status as the data model writes it: false-positive -> FALSE_POSITIVE, Completed -> COMPLETED. */
const upper = (status: unknown) => String(status ?? "").trim().toUpperCase().replace(/[-\s]+/g, "_");

/** The facts for a question: the run the operator picked, else the newest saved one. */
export function mockFactsFor(views: AssessmentView[], picked: AssessmentView | null): MockFacts {
  if (picked) return factsOf(picked, true);
  const newest = [...views].sort((a, b) => b.createdMs - a.createdMs)[0] ?? null;
  return factsOf(newest, false);
}

/** The answer as a text stream, a few words at a time (as a model would stream it). */
export function mockStream(text: string): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const pieces = text.match(/\S+\s*/g) ?? [text];
  let at = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (at >= pieces.length) {
        controller.close();
        return;
      }
      controller.enqueue(encoder.encode(pieces.slice(at, at + 3).join("")));
      at += 3;
      await new Promise((done) => setTimeout(done, 15));
    },
  });
}
