/* The AI Assistant on the Core API: one conversation is one web session, its messages are
   GET /sessions/{id}/messages, and a question is POST /sessions/{id}/chat/stream (the API
   masks it, asks the agent and saves both). The API keeps no cards and no titles: a
   conversation is titled by its first question, and cards show only while a reply streams.
   Server only. */
import "server-only";

import { randomUUID } from "node:crypto";

import { AUTO_TITLE, cleanTitle, CONVERSATION_FORMAT, type Conversation, type ConversationSummary, type StoredMessage } from "../assistant/history-schema";
import { CONVERSATION_ID, type ScopeRef } from "../assistant/protocol";
import { coreFetch, coreJson, CoreError } from "./core";
import { asMain, chatToken, forgetChat } from "./sessions";

/** GET /sessions answer (SessionRead). */
export type CoreSession = { session_id: string; interface: string; session_status: string; created_at: string; closed_at: string | null };
/** GET /sessions/{id}/messages answer (MessageOut). */
export type CoreMessage = { message_id: string; sequence_no: number; role: string; content_masked: string; created_at: string; session_id: string };
/** One knowledge piece the answer cites (SourceRef): masked text, `url` "" when nothing to open. */
export type CoreSource = { ref_id: string; title: string; url: string; source: string; section: string };
/** The DONE event of a chat stream (ChatOut). */
export type CoreChat = { message: CoreMessage; reply: CoreMessage; agent_run_id: string; sources?: CoreSource[] };

export const ALL_RUNS: ScopeRef = { uid: null, label: "All assessments" };
export const MAX_LISTED = 50; // conversations in the History menu
const MAX_CONTENT = 16_000;

export const NO_ANSWER = "No answer was saved for this question.";
export const STILL_ANSWERING = "The answer is still being written. Open this chat again in a moment.";

const time = (iso: string): number => {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) && ms >= 0 ? ms : 0;
};

const titleOf = (messages: CoreMessage[]): string => {
  const first = messages.find((m) => m.role === "user");
  return (first && cleanTitle(first.content_masked, AUTO_TITLE)) || "New chat";
};

/** The API's messages as a saved conversation the page reads (only ids the page accepts). */
export function toConversation(session: Pick<CoreSession, "session_id" | "created_at">, messages: CoreMessage[], answering = false): Conversation {
  const ordered = [...messages].sort((a, b) => a.sequence_no - b.sequence_no);
  const out: StoredMessage[] = [];
  let question: string | null = null;
  // a question the API kept without an answer (the model failed) gets an error reply, so the
  // page offers Retry instead of a question hanging on its own
  const unanswered = (q: StoredMessage, detail = NO_ANSWER) => {
    out.push({ id: randomUUID(), role: "assistant", replyTo: q.id, content: "", cards: [], state: "error", detail, at: q.at });
  };
  for (const m of ordered) {
    if (!CONVERSATION_ID.test(m.message_id)) continue;
    const content = m.content_masked.slice(0, MAX_CONTENT);
    const last = out.at(-1);
    if (m.role === "user" && content.trim()) {
      if (last?.role === "user") unanswered(last);
      out.push({ id: m.message_id, role: "user", content: content.slice(0, 4_000), at: time(m.created_at) });
      question = m.message_id;
    } else if (m.role === "assistant" && question && last?.role === "user" && content.trim()) {
      out.push({ id: m.message_id, role: "assistant", replyTo: question, content, cards: [], state: "done", at: time(m.created_at) });
    }
  }
  const last = out.at(-1);
  if (last?.role === "user") unanswered(last, answering ? STILL_ANSWERING : NO_ANSWER); // the newest may still be coming
  const created = time(session.created_at);
  return {
    format: CONVERSATION_FORMAT,
    id: session.session_id,
    title: titleOf(ordered),
    scope: ALL_RUNS,
    createdAt: created,
    updatedAt: Math.max(created, ...out.map((m) => m.at)),
    messages: out.slice(-200),
  };
}

const messagesOf = (id: string) => asMain((token) => coreJson<CoreMessage[]>(`/sessions/${id}/messages`, { token }));

/** The open web sessions that hold messages, newest use first. */
export async function listConversations(): Promise<ConversationSummary[]> {
  const sessions = await asMain((token) => coreJson<CoreSession[]>("/sessions?interface=web&session_status=ACTIVE", { token }));
  const listed = sessions.filter((s) => CONVERSATION_ID.test(s.session_id)).slice(0, MAX_LISTED);
  const read = await Promise.all(listed.map(async (s) => toConversation(s, await messagesOf(s.session_id))));
  return read
    .filter((c) => c.messages.length > 0)
    .map((c) => ({ id: c.id, title: c.title, scope: c.scope, createdAt: c.createdAt, updatedAt: c.updatedAt, count: c.messages.length }))
    .sort((a, b) => b.updatedAt - a.updatedAt);
}

/** One conversation, or null when the API has no such open web session. */
export async function readConversation(id: string): Promise<Conversation | null> {
  let session: CoreSession;
  try {
    session = await asMain((token) => coreJson<CoreSession>(`/sessions/${id}`, { token }));
  } catch (error) {
    if (error instanceof CoreError && error.status === 404) return null;
    throw error;
  }
  if (session.interface !== "web" || session.session_status !== "ACTIVE") return null;
  const [messages, runs] = await Promise.all([messagesOf(id), asMain((token) => coreJson<{ agent_runs_status: string }[]>(`/sessions/${id}/agent-runs`, { token }))]);
  return toConversation(session, messages, runs[0]?.agent_runs_status === "RUNNING"); // runs: newest first
}

/** Runs `call` with a conversation's token; a token the API no longer knows (it restarted)
    is resumed once and the call made again. */
async function asChat<T>(id: string, call: (token: string) => Promise<T>): Promise<T> {
  try {
    return await call(await chatToken(id));
  } catch (error) {
    if (!(error instanceof CoreError) || error.status !== 401) throw error;
    return call(await chatToken(id, true));
  }
}

/** Closes a conversation's session (the API keeps its messages, the list stops showing it). */
export async function closeConversation(id: string): Promise<void> {
  try {
    await asChat(id, (token) => coreJson(`/sessions/${id}/close`, { method: "POST", token }));
  } catch (error) {
    if (!(error instanceof CoreError) || error.status !== 409) throw error; // closed already
  }
  forgetChat(id);
}

/** Closes every conversation; how many were closed. */
export async function closeAll(): Promise<number> {
  const all = await listConversations();
  for (const c of all) await closeConversation(c.id);
  return all.length;
}

/** One Server-Sent Event of a chat stream. */
export type ChatEvent = { event: "PIECE"; text: string } | { event: "DONE"; chat: CoreChat } | { event: "ERROR"; code: string; message: string };

/** Splits an SSE body into events (an event may be split anywhere; an unknown one is skipped). */
export function createEventReader(onEvent: (event: ChatEvent) => void) {
  let buffer = "";
  const take = (block: string) => {
    let name = "";
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("event:")) name = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    }
    let value: Record<string, unknown>;
    try {
      value = JSON.parse(data.join("\n"));
    } catch {
      return;
    }
    if (name === "PIECE" && typeof value.text === "string") onEvent({ event: "PIECE", text: value.text });
    else if (name === "DONE" && value.reply) onEvent({ event: "DONE", chat: value as unknown as CoreChat });
    else if (name === "ERROR") onEvent({ event: "ERROR", code: String(value.code ?? "ERROR"), message: typeof value.message === "string" ? value.message.slice(0, 400) : "The agent could not answer." });
  };
  return {
    push(chunk: string) {
      buffer += chunk;
      const blocks = buffer.split(/\r?\n\r?\n/);
      buffer = blocks.pop() ?? "";
      for (const block of blocks) if (block.trim()) take(block);
    },
    end() {
      if (buffer.trim()) take(buffer);
      buffer = "";
    },
  };
}

/** Asks in a conversation; the open SSE body. A refusal before the stream starts is a
    CoreError (a chat already running: 409). */
export async function askStream(id: string, question: string, signal: AbortSignal, assessmentId?: string): Promise<ReadableStream<Uint8Array>> {
  const body = assessmentId ? { content: question, assessment_id: assessmentId } : { content: question };
  const response = await asChat(id, (token) => coreFetch(`/sessions/${id}/chat/stream`, { method: "POST", body, token, signal, stream: true }));
  if (!response.body) throw new CoreError(502, "NO_STREAM", "The Core API sent no answer.");
  return response.body;
}
