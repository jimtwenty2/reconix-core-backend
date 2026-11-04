/* Evaluator-run fixes in the AI Assistant: the mock answers a question about the decision and
   about one plan step, a finished run has nothing left to decide, "explain finding 001" shows
   that finding only, and a misspelt view name ("runlog") opens its view. */
import { describe, expect, it } from "vitest";

import { parseView } from "@/components/dashboard/view-url";
import { pickCards } from "@/lib/assistant/cards";
import { readIntent } from "@/lib/assistant/intent";
import { factsOf, intentOf, mockReply } from "@/lib/assistant/models/mock";
import { assessmentView } from "@/lib/data/adapt";

import { sampleAssessments } from "./fixtures";

const PLAN = "1. Discover hosts; 2. Scan open ports (Nmap); 3a. Check TLS (MEDIUM, needs your approval)";

describe("the mock's new answers (shared with the TUI)", () => {
  it.each(["should I approve?", "can I reject it?", "is it safe to run the plan?", "what should I do?"])("%s is answered, not refused", (q) => {
    expect(intentOf(q).id).toBe("decision");
    expect(mockReply(q, { step: "The run waits for you." })).toMatch(/^That's your call/);
  });

  it("still refuses an order", () => {
    expect(intentOf("approve that scope").id).toBe("action");
    expect(intentOf("run step 1").id).toBe("action");
  });

  it("answers one plan step, not the whole plan", () => {
    const answer = mockReply("what does step 2 do?", { plan: PLAN });
    expect(answer).toMatch(/^Step 2: Scan open ports \(Nmap\)\./);
    expect(answer).not.toContain("Discover hosts");
    expect(mockReply("what is step 3A?", { plan: PLAN })).toMatch(/^Step 3a: Check TLS/);
    expect(mockReply("what does step 9 do?", { plan: PLAN })).toContain("There is no step 9");
    expect(mockReply("what does step 2 do?", {})).toContain("no plan yet");
  });
});

describe("a run that waits for nothing", () => {
  it("says nothing is left to decide once it ended", () => {
    const run = sampleAssessments().find((a) => a.status === "Completed")!;
    const step = factsOf(assessmentView(run)).step ?? "";
    expect(step).toContain("nothing is left to decide");
    expect(step).not.toContain("Decide anything");
  });
});

describe("explain finding 001", () => {
  const samples = sampleAssessments();
  const run = samples.find((a) => a.findings.length > 1)!;
  const view = assessmentView(run);

  it("reads the number without its prefix", () => {
    expect(readIntent("explain finding 001").findingNumbers).toEqual([1]);
    expect(readIntent("what about finding #3?").findingNumbers).toEqual([3]);
  });

  it("shows that finding only, not the list", () => {
    const cards = pickCards(samples, view.uid, "explain finding 001");
    expect(cards.map((c) => c.kind)).toEqual(["finding"]);
    const card = cards[0] as Extract<(typeof cards)[number], { kind: "finding" }>;
    expect(Number(/(\d+)$/.exec(card.item.id)?.[1])).toBe(1);
  });
});

describe("view names", () => {
  it.each([
    ["runlog", "log"],
    ["Run-Log", "log"],
    ["report", "reports"],
    ["findings", "findings"],
    ["audit", "overview"],
  ])("?view=%s opens %s", (name, view) => {
    expect(parseView(name)).toBe(view);
  });
});
