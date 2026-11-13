/* Text with its references marked (pure: browser and tests). The API says where each reference
   and topic is named in a passage (spans); this cuts the text into plain parts and marked parts,
   without overlaps (the first-starting, then longest, wins), and cuts a snippet around one
   reference for "Mentions". */

export interface Span {
  type: string;
  ref_id: string;
  start: number;
  end: number;
}
export type Part = { text: string; span: Span | null };

/** The text as plain and marked parts, in order. Spans outside the text are dropped. */
export function partsOf(text: string, spans: readonly Span[]): Part[] {
  const ordered = spans.filter((s) => s.start >= 0 && s.end <= text.length && s.end > s.start).sort((a, b) => a.start - b.start || b.end - a.end);
  const parts: Part[] = [];
  let at = 0;
  for (const s of ordered) {
    if (s.start < at) continue; // overlaps one already marked
    if (s.start > at) parts.push({ text: text.slice(at, s.start), span: null });
    parts.push({ text: text.slice(s.start, s.end), span: s });
    at = s.end;
  }
  if (at < text.length) parts.push({ text: text.slice(at), span: null });
  return parts;
}

/** About `around` characters of text on each side of the first place `type`/`refId` is named,
    with "…" where it was cut, and the spans moved to fit. null: not named in this text. */
export function snippetOf(text: string, spans: readonly Span[], type: string, refId: string, around = 110): { text: string; spans: Span[] } | null {
  const hit = spans.find((s) => s.type === type && s.ref_id === refId);
  if (!hit) return null;
  let from = Math.max(0, hit.start - around);
  let to = Math.min(text.length, hit.end + around);
  // cut at a space where one is near, so words stay whole
  if (from > 0) {
    const space = text.indexOf(" ", from);
    if (space >= 0 && space < hit.start) from = space + 1;
  }
  if (to < text.length) {
    const space = text.lastIndexOf(" ", to);
    if (space > hit.end) to = space;
  }
  const head = from > 0 ? "…" : "";
  const shift = head.length - from;
  const inside = spans.filter((s) => s.start >= from && s.end <= to).map((s) => ({ ...s, start: s.start + shift, end: s.end + shift }));
  return { text: `${head}${text.slice(from, to)}${to < text.length ? "…" : ""}`, spans: inside };
}
