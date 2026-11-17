/* The AI Assistant's question route (signed in; src/proxy.ts checks the session too). In
   order: the launch token, the page's origin, a session, a rate slot (before any reading), the
   body (bytes counted as they arrive) and its shape. The question goes to the Core API
   (POST /sessions/{id}/chat/stream, lib/api/assistant.ts), which masks it, asks the agent with
   the active model (the model picker's: GET /llm-providers) and saves both; a new
   conversation is a new web session. The cards come from the saved data (read here, never
   taken from the request). The answer streams back as NDJSON frames (lib/assistant/protocol.ts);
   the conversation's id also goes in the X-Conversation-Id header, so a page that stops
   before the first frame still knows it. Nothing is logged. */
import { ALL_RUNS, askStream, readConversation } from "@/lib/api/assistant";
import { coreFailure } from "@/lib/api/respond";
import { openChat } from "@/lib/api/sessions";
import { pickCards } from "@/lib/assistant/cards";
import { scopeOf } from "@/lib/assistant/insights";
import { fail, NO_STORE, readJson, refuse } from "@/lib/assistant/access";
import { AUTO_TITLE, cleanTitle } from "@/lib/assistant/history-schema";
import { NDJSON } from "@/lib/assistant/protocol";
import { createLimiter, limitsFromEnv } from "@/lib/assistant/rate";
import { replyStream } from "@/lib/assistant/reply";
import { ChatRequestSchema, MAX_BODY } from "@/lib/assistant/request";
import { assessmentView } from "@/lib/data/adapt";
import { loadApiLibrary } from "@/lib/api/library";

const limiter = createLimiter(...limitsFromEnv());
const GONE = "That conversation is not saved any more. Start a new chat.";

export async function POST(request: Request) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;

  const release = limiter.take();
  if (!release) return fail("Too many questions at once. Wait a moment and ask again.", 429);
  let streaming = false; // from here the reply stream hands the slot back
  try {
    const body = await readJson(request, MAX_BODY);
    if (!body.ok) return body.response;
    const parsed = ChatRequestSchema.safeParse(body.value);
    if (!parsed.success) return fail("The request does not match what the assistant accepts.", 400);
    const { conversationId, uid, question } = parsed.data;

    // cards are facts from the Core API's assessments, picked for the question; the model never
    // makes one. Picked before asking, so the API's answer is read as soon as it starts
    let cards: ReturnType<typeof pickCards> = [];
    let scope = ALL_RUNS;
    try {
      const library = await loadApiLibrary();
      cards = pickCards(library.assessments, uid, question);
      if (uid) {
        const chosen = library.assessments.find((a) => a.uid === uid);
        scope = chosen ? scopeOf(assessmentView(chosen)) : { uid, label: uid };
      }
    } catch {
      cards = [];
      if (uid) scope = { uid, label: uid };
    }

    let id: string;
    let title = cleanTitle(question, AUTO_TITLE) || "New chat";
    const abort = new AbortController();
    request.signal.addEventListener("abort", () => abort.abort(), { once: true });
    let answer: ReadableStream<Uint8Array>;
    try {
      if (conversationId) {
        const existing = await readConversation(conversationId);
        if (!existing) return fail(GONE, 404);
        id = existing.id;
        title = existing.title;
      } else id = await openChat();
      answer = await askStream(id, question, abort.signal);
    } catch (error) {
      return coreFailure(error, "The assistant could not answer.");
    }

    const stream = replyStream({ body: answer, meta: { conversationId: id, title, scope }, cards, abort, release });
    streaming = true;
    return new Response(stream, {
      headers: { ...NO_STORE, "Content-Type": NDJSON, "X-Content-Type-Options": "nosniff", "X-Conversation-Id": id },
    });
  } finally {
    if (!streaming) release();
  }
}
