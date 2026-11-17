"use client";

import { useEffect } from "react";

/**
 * Mounts once. Moves the soft light on whichever .dash-card the pointer is over by writing
 * --mx/--my (read by .dash-card::before). One document listener, rAF-throttled, no layout work
 * beyond a single getBoundingClientRect per move. Off on coarse pointers.
 */
export function CardCursorLight() {
  useEffect(() => {
    if (window.matchMedia("(pointer: coarse)").matches) return;
    let raf = 0;
    let el: HTMLElement | null = null;
    let clientX = 0;
    let clientY = 0;
    const apply = () => {
      raf = 0;
      if (!el) return;
      const r = el.getBoundingClientRect();
      el.style.setProperty("--mx", `${clientX - r.left}px`);
      el.style.setProperty("--my", `${clientY - r.top}px`);
    };
    const onMove = (e: PointerEvent) => {
      const card = (e.target as Element)?.closest?.(".dash-card") as HTMLElement | null;
      el = card;
      if (!card) return;
      clientX = e.clientX;
      clientY = e.clientY;
      if (!raf) raf = requestAnimationFrame(apply);
    };
    document.addEventListener("pointermove", onMove, { passive: true });
    return () => {
      document.removeEventListener("pointermove", onMove);
      cancelAnimationFrame(raf);
    };
  }, []);
  return null;
}
