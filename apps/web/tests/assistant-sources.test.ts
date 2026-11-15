/* The knowledge a chat answer cites (the API's ChatOut `sources`, on its DONE event): the
   server turns it into one `sources` frame (lib/assistant/reply.ts) and the page shows a muted
   line under the reply ([ref_id] title, linked only when the url is http(s)). A bad or empty
   list simply sends no frame and never breaks the answer. */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SourcesUsed } from "@/components/assistant/sources-used";
import type { SourceRef } from "@/lib/assistant/protocol";
import { type Frame, parseFrame } from "@/lib/assistant/protocol";

const ID = "0b0e2d55-1c5a-4b1e-9b8c-2f1d3c4b5a69";
const LOG4J = { ref_id: "CVE-2021-44228", title: "Apache Log4j2 JNDI features remote code execution", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", source: "CVE", section: "Description" };

/** The real reply stream (lib/assistant/reply.ts) over a DONE event carrying these `sources`. */
async function framesFor(sources: unknown): Promise<Frame[]> {
  const { replyStream } = await import("@/lib/assistant/reply");
  const done = { message: {}, reply: { content_masked: "Log4j is the one." }, agent_run_id: "r", sources };
  const body = new Response(`event: DONE\ndata: ${JSON.stringify(done)}\n\n`).body!;
  const meta = { conversationId: ID, title: "t", scope: { uid: null, label: "All assessments" } };
  const text = await new Response(replyStream({ body, meta, cards: [], abort: new AbortController(), release: () => {} })).text();
  return text.split("\n").map(parseFrame).filter((f) => f !== null);
}

const cited = (sources: unknown) => renderToStaticMarkup(createElement(SourcesUsed, { sources: sources as SourceRef[] | undefined }));

describe("the sources frame", () => {
  it("carries the citations a DONE event sent, after the answer and before done", async () => {
    const frames = await framesFor([LOG4J]);
    expect(frames).toContainEqual({ t: "sources", items: [LOG4J] });
    const kinds = frames.map((f) => f.t);
    expect(kinds.filter((k) => k === "meta")).toHaveLength(1); // no second meta: it would re-run setOpened
    expect(kinds.indexOf("sources")).toBe(kinds.lastIndexOf("final") + 1); // after the answer, right before done
    expect(frames.at(-1)).toEqual({ t: "done" });
  });

  it("sends nothing when the answer cited no sources", async () => {
    for (const sources of [[], undefined, null]) {
      const frames = await framesFor(sources);
      expect(frames.some((f) => f.t === "sources")).toBe(false);
      expect(frames).toContainEqual({ t: "final", text: "Log4j is the one." });
      expect(frames.at(-1)).toEqual({ t: "done" });
    }
  });

  it("drops a sources list it cannot trust, and still answers", async () => {
    for (const sources of [
      "not a list",
      [null],
      [{ ref_id: "CVE-1", title: "t".repeat(500), url: "", source: "CVE", section: "" }], // over the cap
      [{ ref_id: "CVE-1", title: "t", url: 8080, source: "CVE", section: "" }], // a url that is not a string
      { ref_id: "CVE-1" }, // not a list
    ]) {
      const frames = await framesFor(sources);
      expect(frames.some((f) => f.t === "sources")).toBe(false);
      expect(frames.at(-1)).toEqual({ t: "done" });
    }
  });
});

describe("the citation line", () => {
  it("shows the ref_id and the title as plain text", () => {
    const html = cited([LOG4J]);
    expect(html).toContain("CVE-2021-44228");
    expect(html).toContain("Apache Log4j2 JNDI features remote code execution");
  });

  it("links the title only when the url is http(s)", () => {
    expect(cited([LOG4J])).toContain(`href="${LOG4J.url}"`);
    expect(cited([LOG4J])).toContain('target="_blank"');
    expect(cited([LOG4J])).toContain('rel="noreferrer noopener"');
    for (const url of ["javascript:alert(1)", "data:text/html,<script>", "file:///c:/windows", "//evil.example/x", "ftp://evil.example", ""]) {
      expect(cited([{ ...LOG4J, url }])).not.toContain("<a");
    }
  });

  it("shows the ref_id alone when there is no title, and never the markup a title holds", () => {
    expect(cited([{ ...LOG4J, title: "", url: "" }])).toContain("CVE-2021-44228");
    const html = cited([{ ...LOG4J, title: "<img src=x onerror=alert(1)>", url: "" }]);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });

  it("shows nothing when there is nothing cited", () => {
    expect(cited([])).toBe("");
    expect(cited(undefined)).toBe("");
  });
});
