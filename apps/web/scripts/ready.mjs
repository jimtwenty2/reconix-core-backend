/* When the dashboard is really serving — for scripts/serve.mjs.

   Next.js prints "✓ Ready in …ms" and binds the port BEFORE it checks whether another
   `next dev` already holds apps/web/.next/dev/lock, and then aborts. Announcing on that line
   alone told the TUI a dashboard was ready that was already dying, so /web wrote a sign-in link
   for a dead port (QA-LOCAL-WEB-REPORT, QAL-001). The line now only starts the check: the child
   must still be alive and the port must answer, twice, before anything is written or announced.
   Next.js's own words for "something else is in the way" end it at once. */
import http from "node:http";

/** The exit code the TUI reads as "another dashboard is in the way" (reconix/web_server.py). */
export const PORTS_BUSY = 2;

/** Next.js saying it: its duplicate-dev-server abort, or a port taken under it. */
export const BUSY = /another next dev server is already running|EADDRINUSE|address already in use/i;

const READY = /ready/i;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** True when something answers on 127.0.0.1:`port` (any HTTP reply: it is serving). */
export function answers(port, path = "/login", timeout = 2000) {
  return new Promise((resolve) => {
    const request = http.get({ host: "127.0.0.1", port: Number(port), path, timeout }, (response) => {
      response.resume();
      resolve(true);
    });
    request.on("timeout", () => request.destroy());
    request.on("error", () => resolve(false));
  });
}

/**
 * Watch a `next dev` / `next start` child until the dashboard really serves, or until it is
 * clear it never will.
 *
 * `child` is the spawned process; its stdout and stderr are read, never consumed. `probe` asks
 * whether the port answers; `tries` probes follow the "Ready" line, `pause` ms apart (the port is
 * briefly live, so the first one waits too) and `needed` of them must answer in a row with the
 * child still alive. `wait` is the sleep, so a test can run the loop without the clock.
 *
 * @param {{probe: () => Promise<boolean>, tries?: number, pause?: number, needed?: number,
 *          wait?: (ms: number) => Promise<unknown>}} options
 * @returns {Promise<{ready: boolean, code?: number}>} what serve.mjs exits with, when not ready
 */
export function waitForReady(child, { probe, tries = 10, pause = 600, needed = 2, wait = sleep }) {
  return new Promise((resolve) => {
    let done = false;
    let busy = false;
    let confirming = false;

    const finish = (result) => {
      if (done) return;
      done = true;
      resolve(result);
    };

    const read = (chunk) => {
      const text = String(chunk);
      if (BUSY.test(text)) {
        busy = true;
        finish({ ready: false, code: PORTS_BUSY });
      } else if (READY.test(text)) {
        confirm();
      }
    };

    /* The "Ready" line, then: still alive? does the port answer? */
    async function confirm() {
      if (confirming) return;
      confirming = true;
      let seen = 0;
      for (let i = 0; i < tries && !done; i++) {
        await wait(pause);
        if (done) return;
        if (child.exitCode !== null && child.exitCode !== undefined) return; // its own exit answers
        seen = (await probe()) ? seen + 1 : 0;
        if (seen >= needed) return finish({ ready: true });
      }
      finish({ ready: false, code: 1 });
    }

    child.stdout?.on("data", read);
    child.stderr?.on("data", read);
    child.on("exit", (code) => finish({ ready: false, code: busy ? PORTS_BUSY : code || 1 }));
  });
}
