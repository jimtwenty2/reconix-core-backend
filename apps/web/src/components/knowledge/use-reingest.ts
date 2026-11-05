"use client";

/* The knowledge re-ingest job (the Core API runs it): read when the page is shown, followed
   every POLL_MS while it runs, and `onDone` once it ends (the graph and the content are read
   again). Its end is told in a toast. */
import { useCallback, useEffect, useRef, useState } from "react";

import { toast } from "@/components/ui/toast";
import * as api from "@/lib/knowledge/client";

const POLL_MS = 1200;

export function useReingest(shown: boolean, onDone: () => void) {
  const [job, setJob] = useState<api.Reingest | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const done = useRef(onDone);
  useEffect(() => {
    done.current = onDone;
  }, [onDone]);

  // read it when the page is shown
  useEffect(() => {
    if (!shown) return;
    let live = true;
    void api.loadReingest().then((r) => {
      if (live && r.ok) setJob(r.value);
    });
    return () => {
      live = false;
    };
  }, [shown]);

  // follow it while it runs
  const running = job?.status === "RUNNING";
  useEffect(() => {
    if (!running) return;
    let live = true;
    const timer = setInterval(() => {
      void api.loadReingest().then((r) => {
        if (!live || !r.ok) return;
        setJob(r.value);
        if (r.value.status === "COMPLETED") {
          const n = r.value.new_ingested;
          toast(
            r.value.scope === "NEW"
              ? `Ingested ${n} ${n === 1 ? "document" : "documents"}: the AI Assistant can search ${n === 1 ? "it" : "them"} now.`
              : `Re-ingest done: ${r.value.public_pieces} built-in pieces, ${r.value.add_ons_done} ${r.value.add_ons_done === 1 ? "document" : "documents"} (${n} new).`,
          );
          done.current();
        } else if (r.value.status === "FAILED") {
          toast(`Re-ingest failed: ${r.value.error_message ?? "the Core API could not finish it."}`, "error");
          done.current();
        }
      });
    }, POLL_MS);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [running]);

  /** NEW: only the documents waiting; ALL: the built-in knowledge and every document. */
  const start = useCallback(async (scope: "NEW" | "ALL") => {
    setStarting(true);
    setError(null);
    const r = await api.startReingest(scope);
    setStarting(false);
    if (r.ok) setJob(r.value);
    else setError(r.detail);
  }, []);

  return { job, start, starting, error };
}
