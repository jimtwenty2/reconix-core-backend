import { describe, expect, it } from "vitest";

import { canRetryLast, createEpochGuard, isStaleStream } from "@/lib/assistant/chat-state";

describe("chat state guards", () => {
  it("blocks retry before slicing messages when reading is active or model is unconfigured", () => {
    const msgs = [
      { id: "u1", role: "user" as const, content: "hi" },
      { id: "a1", role: "assistant" as const, content: "", state: "error" as const, question: "hi" },
    ];
    expect(canRetryLast(msgs, { hasStream: false, reading: true, configured: true })).toBeNull();
    expect(canRetryLast(msgs, { hasStream: false, reading: false, configured: false })).toBeNull();
    expect(canRetryLast(msgs, { hasStream: true, reading: false, configured: true })).toBeNull();
    expect(canRetryLast(msgs, { hasStream: false, reading: false, configured: true })?.id).toBe("a1");
  });

  it("identifies halted or superseded stream controllers so finally/catch ignores stale runs", () => {
    const c1 = new AbortController();
    const c2 = new AbortController();
    expect(isStaleStream(null, c1)).toBe(true);
    expect(isStaleStream(c2, c1)).toBe(true);
    expect(isStaleStream(c1, c1)).toBe(false);
    c1.abort();
    expect(isStaleStream(c1, c1)).toBe(true);
  });

  it("epoch guard invalidates in-flight history loads when a newer load or delete occurs", () => {
    const guard = createEpochGuard();
    const req1 = guard.next();
    expect(guard.isCurrent(req1)).toBe(true);
    guard.next();
    expect(guard.isCurrent(req1)).toBe(false);
  });
});
