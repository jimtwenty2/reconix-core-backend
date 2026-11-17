/* The knowledge a chat answer cites (the API's ChatOut `sources`, on its DONE event): the
   server turns it into one `sources` frame (lib/assistant/reply.ts) and the page shows a muted
   line under the reply ([ref_id] title, linked only when the url is http(s)). A bad or empty
   list simply sends no frame and never breaks the answer. */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { isKnowledgeDocSource, partNumberOf, SourcePreviewCard, SourcesUsed } from "@/components/assistant/sources-used";
import { GraphDetails } from "@/components/knowledge/graph-details";
import type { Passages } from "@/components/knowledge/use-passages";
import { buildGraph, REF_TYPES } from "@/lib/knowledge/graph";
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

  it("renders a clickable button for uploaded USER_DOC sources with their passage part", () => {
    const docSource: SourceRef = {
      ref_id: "d10f0984-d24e-439f-a78b-a23995bae172",
      title: "owasp-top-10-2025.md",
      url: "",
      source: "USER_DOC",
      section: "/Part 31/",
    };
    expect(isKnowledgeDocSource(docSource)).toBe(true);
    expect(partNumberOf(docSource.section)).toBe(31);
    const html = cited([docSource]);
    expect(html).toContain("<button");
    expect(html).toContain('class="ai-source-link"');
    expect(html).toContain("owasp-top-10-2025.md (Part 31)");
    expect(html).not.toContain(`[${docSource.ref_id}]`);
    expect(cited([{ ...LOG4J, url: "" }])).not.toContain("<button");
    expect(isKnowledgeDocSource({ ...docSource, ref_id: "not-a-uuid" })).toBe(false);
    expect(partNumberOf("/Part 0/")).toBeNull();
  });

  it("highlights the cited passage in GraphDetails when opened via initialPart", () => {
    const id = "d10f0984-d24e-439f-a78b-a23995bae172";
    const graph = buildGraph([{ id, name: "owasp-top-10-2025.md", kind: "md", chunks: 2, ingested: true }], {}, new Set(REF_TYPES), false);
    const node = graph.byId.get(`doc:${id}`)!;
    const passages: Passages = {
      content: {
        [id]: {
          status: "ready",
          total: 2,
          error: null,
          passages: [
            { index: 0, text: "First passage", spans: [] },
            { index: 1, text: "Cited passage content", spans: [] },
          ],
        },
      },
      load: () => {},
      more: () => {},
      all: () => {},
      ensure: () => {},
      forget: () => {},
    };
    const html = renderToStaticMarkup(
      createElement(GraphDetails, {
        graph,
        node,
        onFocus: () => {},
        passages,
        initialPart: 1,
        highlightAnswer: "It came from the cited passage content here.",
      }),
    );
    expect(html).toContain('data-index="0" class="kn-passage"');
    expect(html).toContain('data-index="1" class="kn-passage is-found"');
    expect(html).toContain('<mark class="kn-used">');
  });

  it("renders a hover SourcePreviewCard with color-highlighted passage spans and about summary", () => {
    const docSource: SourceRef = {
      ref_id: "d10f0984-d24e-439f-a78b-a23995bae172",
      title: "owasp-top-10-2025.md",
      url: "",
      source: "USER_DOC",
      section: "/Part 31/",
    };
    const passageHtml = renderToStaticMarkup(
      createElement(SourcePreviewCard, {
        source: docSource,
        answer: "Broken Access Control maps to CWE-200 and OWASP SAMM.",
        preview: {
          kind: "passage",
          title: docSource.title,
          part: 31,
          passage: {
            index: 30,
            text: "Unrelated heading line.\nBroken Access Control maps to CWE-200 and OWASP SAMM.",
            spans: [{ type: "CWE", ref_id: "CWE-200", start: 54, end: 61 }],
          },
        },
      }),
    );
    expect(passageHtml).toContain("ai-source-card");
    expect(passageHtml).toContain('data-type="DOC"');
    expect(passageHtml).toContain("Document · Part 31");
    expect(passageHtml).toContain('<mark class="kn-used">');
    expect(passageHtml).toContain('class="kn-mark" data-type="CWE"');
    expect(passageHtml).toContain(">CWE-200<");

    const aboutHtml = renderToStaticMarkup(
      createElement(SourcePreviewCard, {
        source: LOG4J,
        preview: {
          kind: "about",
          refType: "CVE",
          title: LOG4J.title,
          text: "Remote code execution via JNDI lookup.",
          source: "CVE",
        },
      }),
    );
    expect(aboutHtml).toContain('data-type="CVE"');
    expect(aboutHtml).toContain("Remote code execution via JNDI lookup.");
    expect(aboutHtml).toContain("Opens external reference");
  });

  it("shows nothing when there is nothing cited", () => {
    expect(cited([])).toBe("");
    expect(cited(undefined)).toBe("");
  });
});
