/* The Run log view's data (derive-run-log.ts) from the sample runs: every timeline entry shows
   once, as a message or as a step of a folded block, masked, with no name in front of a message. */
import { describe, expect, it } from "vitest";

import { runLogData, secondsText } from "@/components/dashboard/derive-run-log";
import { assessmentView } from "@/lib/data/adapt";

import { sampleAssessments } from "./fixtures";

const samples = sampleAssessments();

describe("runLogData", () => {
  it("shows every timeline entry once: a message, or a step of a block", () => {
    for (const a of samples) {
      const data = runLogData(assessmentView(a));
      const shown = data.items.reduce((n, i) => n + (i.type === "message" ? 1 : i.steps.length), 0);
      expect(shown, a.uid).toBe(a.timeline.length);
      const keys = data.items.map((i) => i.key);
      expect(new Set(keys).size, a.uid).toBe(keys.length);
    }
  });

  it("never puts two blocks side by side: a message always sits between them", () => {
    for (const a of samples) {
      const types = runLogData(assessmentView(a)).items.map((i) => i.type);
      expect(types.some((t, n) => t === "block" && types[n + 1] === "block"), a.uid).toBe(false);
    }
  });

  it("folds a finished run into done blocks that name the work and count the blocked steps", () => {
    const done = samples.find((a) => a.status === "Completed" && a.verdicts.some((v) => !v.allowed));
    expect(done).toBeDefined();
    const blocks = runLogData(assessmentView(done!)).items.filter((i) => i.type === "block");
    expect(blocks.length).toBeGreaterThan(0);
    expect(blocks.every((b) => b.type === "block" && b.state === "done")).toBe(true);
    expect(blocks.some((b) => b.type === "block" && /^Worked/.test(b.title))).toBe(true);
    expect(blocks.reduce((n, b) => n + (b.type === "block" ? b.blocked : 0), 0)).toBeGreaterThan(0);
  });

  it("masks a secret in a message and in a step", () => {
    const a = structuredClone(samples[0]);
    const line = { seq: 9998, at: null, type: "chat" as const, who: "reconix", kind: "text", text: "password=hunter2", tone: "default", rows: [] };
    a.timeline.push(line, { ...line, seq: 9999, type: "activity", who: "TOOL", kind: "line" });
    const text = JSON.stringify(runLogData(assessmentView(a)));
    expect(text).not.toContain("hunter2");
  });

  it("writes durations the way the TUI does", () => {
    expect([secondsText(0), secondsText(45), secondsText(187), secondsText(3720)]).toEqual(["0s", "45s", "3m 07s", "1h 02m"]);
  });
});
