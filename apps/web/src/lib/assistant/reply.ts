/* One answer as the NDJSON stream the page reads (protocol.ts), server only: `meta`, the cards,
   the agent's text as the Core API streams it (`PIECE` events), `final` with the reply the API
   saved (its `DONE` event: the last words arrive only there), an `error` if the API could not
   answer, then `done`. The API saves the question and the reply itself, even when the page
   stops (Stop aborts the request to the API too). The rate slot is handed back at the very
   end. Nothing here logs the question or the answer. */
import "server-only";

import { createEventReader } from "../api/assistant";
import type { ScopeRef } from "./protocol";
import { type Card, encodeFrame, type Frame, SourcesSchema } from "./protocol";

export interface ReplyInput {
  body: ReadableStream<Uint8Array>; // the API's SSE answer
  meta: { conversationId: string; title: string; scope: ScopeRef };
  cards: Card[];
  abort: AbortController; // aborts the request to the API
  release: () => void; // the rate slot
}

export function replyStream({ body, meta, cards, abort, release }: ReplyInput): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let open = true;

  const run = async (controller: ReadableStreamDefaultController<Uint8Array>) => {
    const send = (frame: Frame) => {
      if (!open) return;
      try {
        controller.enqueue(encoder.encode(encodeFrame(frame)));
      } catch {
        open = false; // the page went away
      }
    };
    send({ t: "meta", ...meta });
    for (const card of cards) send({ t: "card", card });

    let ended = false;
    const events = createEventReader((event) => {
      if (event.event === "PIECE") send({ t: "text", delta: event.text.slice(0, 20_000) });
      else if (event.event === "DONE") {
        ended = true;
        const text = event.chat.reply.content_masked.slice(0, 20_000);
        if (text.trim()) send({ t: "final", text });
        else send({ t: "error", detail: "The model sent an empty answer." }); // empty-reply.ts
        const cited = SourcesSchema.safeParse(event.chat.sources); // nothing cited, or a bad list: no frame, never a throw
        if (cited.success) send({ t: "sources", items: cited.data });
      } else {
        ended = true;
        send({ t: "error", detail: event.message });
      }
    });
    try {
      const reader = body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        events.push(decoder.decode(value, { stream: true }));
      }
      events.push(decoder.decode());
      events.end();
      if (!ended) send({ t: "error", detail: "The answer broke off before it ended." });
    } catch {
      if (!abort.signal.aborted) send({ t: "error", detail: "The Core API stopped answering." });
    }
    send({ t: "done" });
    release();
    if (open) {
      open = false;
      try {
        controller.close();
      } catch {
        // already cancelled
      }
    }
  };

  return new ReadableStream<Uint8Array>({
    start(controller) {
      void run(controller);
    },
    cancel() {
      open = false;
      abort.abort();
    },
  });
}
