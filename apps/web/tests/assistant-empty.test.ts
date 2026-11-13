/* The page's reading of a reply that ended with nothing (components/assistant/empty-reply.ts):
   the server's "empty answer" error becomes its own friendlier state with Retry, while every other
   failure keeps its detail. The real replyStream (lib/assistant/reply.ts) is driven with a Core API
   answer that holds nothing, so a reword of its message fails here. */
import { afterEach, describe, expect, it, vi } from "vitest";

import { EMPTY_ANSWER, EMPTY_REPLY, isEmptyReply, NO_EXPLANATION } from "@/components/assistant/empty-reply";
import type { Card, ChatMessage } from "@/components/assistant/types";
import { parseFrame } from "@/lib/assistant/protocol";

const reply = (over: Partial<ChatMessage>): ChatMessage => ({ id: "r", role: "assistant", content: "", cards: [], state: "error", ...over });
const findings: Card = { kind: "findings", total: 0, counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, NONE: 0 }, items: [], runs: 0 };

/** What the real reply stream says when the model answers with nothing. */
async function emptyAnswerDetail(cards: Card[]): Promise<string> {
  const { replyStream } = await import("@/lib/assistant/reply");
  const done = { message: {}, reply: { content_masked: "" }, agent_run_id: "r" };
  const body = new Response(`event: DONE\ndata: ${JSON.stringify(done)}\n\n`).body!;
  const meta = { conversationId: "0b0e2d55-1c5a-4b1e-9b8c-2f1d3c4b5a69", title: "t", scope: { uid: null, label: "All assessments" } };
  const stream = replyStream({ body, meta, cards, abort: new AbortController(), release: () => {} });
  const text = await new Response(stream).text();
  const frames = text.split("\n").map(parseFrame).filter((f) => f !== null);
  expect(frames.at(-1)).toEqual({ t: "done" });
  const error = frames.find((f) => f.t === "error");
  if (!error || error.t !== "error") throw new Error("no error frame");
  return error.detail;
}

describe("isEmptyReply", () => {
  afterEach(() => vi.restoreAllMocks());

  it("is what the server says of a model that answered nothing", async () => {
    const detail = await emptyAnswerDetail([]);
    expect(EMPTY_ANSWER.test(detail)).toBe(true);
    expect(isEmptyReply(reply({ detail }))).toBe(true);
  });
  it("is also a reply whose cards came but whose text is empty (no explanation)", async () => {
    const detail = await emptyAnswerDetail([findings]);
    expect(isEmptyReply(reply({ cards: [findings], detail }))).toBe(true);
  });
  it("is not any other failure, nor a missing detail", () => {
    expect(isEmptyReply(reply({ detail: "The AI model answered with HTTP 500." }))).toBe(false);
    expect(isEmptyReply(reply({ detail: "The connection to the assistant broke off." }))).toBe(false);
    expect(isEmptyReply(reply({ detail: "The answer broke off before it ended." }))).toBe(false);
    expect(isEmptyReply(reply({}))).toBe(false);
  });
  it("is never a reply that holds text, or one that was stopped or finished", () => {
    expect(isEmptyReply(reply({ content: "Some text", detail: "The model sent an empty answer." }))).toBe(false);
    expect(isEmptyReply(reply({ state: "stopped", detail: "The model sent an empty answer." }))).toBe(false);
    expect(isEmptyReply(reply({ state: undefined }))).toBe(false);
    expect(isEmptyReply(reply({ state: "streaming" }))).toBe(false);
    expect(isEmptyReply({ role: "user", content: "", state: "error", detail: "The model sent an empty answer." })).toBe(false);
  });
  it("says so plainly, with a way on", () => {
    expect(EMPTY_REPLY.title).toBe("The model returned nothing");
    expect(EMPTY_REPLY.body).toMatch(/try asking again/i);
    expect(NO_EXPLANATION.body).toMatch(/try asking again/i);
  });
});
