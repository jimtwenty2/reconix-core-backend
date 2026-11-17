export interface ChatStateMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  state?: string;
  question?: string;
}

export function canStartAsk(params: { question: string; hasStream: boolean; reading: boolean; configured: boolean }): boolean {
  return Boolean(params.question && !params.hasStream && !params.reading && params.configured);
}

export function canRetryLast(
  messages: readonly ChatStateMessage[],
  params: { hasStream: boolean; reading: boolean; configured: boolean },
): ChatStateMessage | null {
  if (params.hasStream || params.reading || !params.configured) return null;
  const last = messages.at(-1);
  return last?.role === "assistant" && last.state === "error" && last.question ? last : null;
}

export function isStaleStream(active: AbortController | null, mine: AbortController): boolean {
  return active !== mine || mine.signal.aborted;
}
