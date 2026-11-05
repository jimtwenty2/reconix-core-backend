"use client";

/* The documents' content, read from the Core API when first needed and kept while the page is
   open: a page of passages at a time ("Load more" asks for the next), so a long document never
   comes all at once. `all` reads up to MENTION_PAGES pages, for the snippets of "Mentions". */
import { useCallback, useRef, useState } from "react";

import * as api from "@/lib/knowledge/client";

export type DocContent = { status: "loading" | "ready" | "error"; total: number; passages: api.Passage[]; error: string | null };

const PAGE = 50;
const MENTION_PAGES = 4;

export function usePassages() {
  const [content, setContent] = useState<Record<string, DocContent>>({});
  const asked = useRef(new Set<string>());

  const page = useCallback(async (id: string, offset: number): Promise<boolean> => {
    const result = await api.loadPassages(id, offset, PAGE);
    setContent((c) => {
      const was = c[id];
      if (!result.ok) return { ...c, [id]: { status: "error", total: was?.total ?? 0, passages: was?.passages ?? [], error: result.detail } };
      const passages = [...(offset === 0 ? [] : (was?.passages ?? [])), ...result.value.passages];
      return { ...c, [id]: { status: "ready", total: result.value.total, passages, error: null } };
    });
    return result.ok && offset + PAGE < result.value.total;
  }, []);

  /** The first page of a document's passages (once). */
  const load = useCallback(
    (id: string) => {
      if (asked.current.has(id)) return;
      asked.current.add(id);
      setContent((c) => ({ ...c, [id]: { status: "loading", total: 0, passages: [], error: null } }));
      void page(id, 0);
    },
    [page],
  );

  /** The next page. */
  const more = useCallback(
    (id: string) => {
      const have = content[id]?.passages.length ?? 0;
      void page(id, have);
    },
    [content, page],
  );

  /** Up to MENTION_PAGES pages (for snippets). */
  const all = useCallback(
    (id: string) => {
      if (asked.current.has(`all:${id}`)) return;
      asked.current.add(`all:${id}`);
      asked.current.add(id);
      setContent((c) => (c[id] ? c : { ...c, [id]: { status: "loading", total: 0, passages: [], error: null } }));
      void (async () => {
        for (let p = 0, go = true; go && p < MENTION_PAGES; p++) go = await page(id, p * PAGE);
      })();
    },
    [page],
  );

  /** Forget a document (removed, or reloaded). */
  const forget = useCallback((id: string) => {
    asked.current.delete(id);
    asked.current.delete(`all:${id}`);
    setContent((c) => {
      const next = { ...c };
      delete next[id];
      return next;
    });
  }, []);

  return { content, load, more, all, forget };
}

export type Passages = ReturnType<typeof usePassages>;
