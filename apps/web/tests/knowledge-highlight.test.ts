/* Marking references in a passage, and the snippets of "Mentions" (lib/knowledge/highlight.ts). */
import { describe, expect, it } from "vitest";

import { partsOf, snippetOf } from "@/lib/knowledge/highlight";

const text = "Use sqlmap for SQL injection (CWE-89) in the search form.";
const span = (type: string, ref_id: string, word: string) => ({ type, ref_id, start: text.indexOf(word), end: text.indexOf(word) + word.length });
const spans = [span("TOOL", "SQLMAP", "sqlmap"), span("TOPIC", "sql-injection", "sqlmap"), span("TOPIC", "sql-injection", "SQL injection"), span("CWE", "CWE-89", "CWE-89")];

describe("partsOf", () => {
  it("marks every reference once, keeps the text whole and drops overlaps", () => {
    const parts = partsOf(text, spans);
    expect(parts.map((p) => p.text).join("")).toBe(text);
    expect(parts.filter((p) => p.span).map((p) => [p.span!.type, p.text])).toEqual([
      ["TOOL", "sqlmap"],
      ["TOPIC", "SQL injection"],
      ["CWE", "CWE-89"],
    ]);
  });
  it("ignores spans outside the text", () => {
    expect(partsOf("short", [{ type: "CWE", ref_id: "CWE-1", start: 2, end: 99 }])).toEqual([{ text: "short", span: null }]);
  });
});

describe("snippetOf", () => {
  it("cuts around the first place a reference is named, with its marks moved to fit", () => {
    const long = `${"a ".repeat(200)}${text}${" b".repeat(200)}`;
    const shift = 400;
    const moved = spans.map((s) => ({ ...s, start: s.start + shift, end: s.end + shift }));
    const snip = snippetOf(long, moved, "CWE", "CWE-89", 40)!;
    expect(snip.text.startsWith("…")).toBe(true);
    expect(snip.text.endsWith("…")).toBe(true);
    const cwe = snip.spans.find((s) => s.type === "CWE")!;
    expect(snip.text.slice(cwe.start, cwe.end)).toBe("CWE-89");
  });
  it("is null when the reference is not named there", () => {
    expect(snippetOf(text, spans, "CVE", "CVE-2021-44228")).toBeNull();
  });
});
