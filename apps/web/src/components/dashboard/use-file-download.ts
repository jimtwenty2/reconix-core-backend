"use client";

/* Fetching a report file, then saving it (the Report view's downloads, api-report-list.tsx). A
   file is fetched rather than linked so that a refusal is shown, not saved: the whole file is
   awaited, then that one blob downloads. A redirect is never followed (it would be the sign-in
   page, saved under the report's name). One request at a time per owner: a new one aborts the
   one in flight, and answers to an older request are dropped. */
import { useCallback, useEffect, useRef } from "react";

/** Save a fetched file under `name` (one click on a temporary link to the blob). */
export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

export const fileNameOf = (disposition: string | null) => disposition?.match(/filename="([A-Za-z0-9._-]+)"/)?.[1] ?? null;

/** A fetch that gives up after `ms` (and when `signal` aborts), and fails on a redirect. */
export function fetchWithin(href: string, ms: number, signal: AbortSignal, accept: string): Promise<Response> {
  const timeout = AbortSignal.timeout(ms);
  return fetch(href, { credentials: "same-origin", headers: { accept }, redirect: "error", signal: AbortSignal.any([signal, timeout]) });
}

export interface Ticket {
  signal: AbortSignal;
  /** Whether this is still the current request. */
  mine: () => boolean;
  /** Frees the slot (only if this request still holds it). */
  done: () => void;
}

/** One request at a time: `begin()` aborts the one in flight and hands out the new one's ticket. */
export function useOneRequest() {
  const inflight = useRef<AbortController | null>(null);
  const serial = useRef(0); // the current request's number: answers to an older one are dropped

  const abort = useCallback(() => {
    inflight.current?.abort();
    inflight.current = null;
    serial.current += 1;
  }, []);
  useEffect(() => abort, [abort]); // unmount

  const begin = useCallback((): Ticket => {
    abort();
    const controller = new AbortController();
    inflight.current = controller;
    const id = serial.current;
    const mine = () => serial.current === id && !controller.signal.aborted;
    const done = () => {
      if (mine()) inflight.current = null;
    };
    return { signal: controller.signal, mine, done };
  }, [abort]);

  return { begin, abort };
}
