/* scripts/ready.mjs: when scripts/serve.mjs may announce a ready dashboard (QAL-001). A "Ready"
   line on its own is not enough — Next.js prints it, binds the port and only then aborts over
   another next dev's lock, so the TUI was told a dying dashboard was ready. */
import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { describe, expect, it } from "vitest";

import { answers, PORTS_BUSY, waitForReady } from "../scripts/ready.mjs";

/** A `next dev` stand-in: two output streams, an exit code and a death it can be told to die. */
function fakeChild() {
  const child = Object.assign(new EventEmitter(), {
    stdout: new EventEmitter(),
    stderr: new EventEmitter(),
    exitCode: null as number | null,
    say(text: string) {
      child.stdout.emit("data", text);
    },
    die(code: number, lastWords = "") {
      if (lastWords) child.stderr.emit("data", lastWords);
      child.exitCode = code;
      child.emit("exit", code);
    },
  });
  return child;
}

const instantly = async () => {};

describe("waitForReady", () => {
  it("does not call a dashboard ready when it prints Ready and then dies", async () => {
    const child = fakeChild();
    const watch = waitForReady(child, {
      probe: async () => true, // the port really is live for a moment, as in the bug
      wait: async () => child.die(1, "⨯ Another next dev server is already running.\n"),
    });
    child.say("✓ Ready in 1965ms\n");
    expect(await watch).toEqual({ ready: false, code: PORTS_BUSY });
  });

  it("reads Next.js's duplicate-dev-server line as the busy exit code, whenever it arrives", async () => {
    const child = fakeChild();
    const watch = waitForReady(child, { probe: async () => true, wait: instantly });
    child.stderr.emit("data", "⨯ Another next dev server is already running.\n");
    expect(await watch).toEqual({ ready: false, code: PORTS_BUSY });
  });

  it("announces once the child is alive and the port answers twice over", async () => {
    const child = fakeChild();
    let probes = 0;
    const watch = waitForReady(child, {
      probe: async () => ++probes > 1, // the first probe is too early
      wait: instantly,
    });
    child.say("✓ Ready in 1965ms\n");
    expect(await watch).toEqual({ ready: true });
    expect(probes).toBe(3);
  });

  it("fails with the child's own code when it dies before it is ever ready", async () => {
    const child = fakeChild();
    const watch = waitForReady(child, { probe: async () => true, wait: instantly });
    child.die(7);
    expect(await watch).toEqual({ ready: false, code: 7 });
  });

  it("gives up when Ready came but the port never answers", async () => {
    const child = fakeChild();
    const watch = waitForReady(child, { probe: async () => false, tries: 3, wait: instantly });
    child.say("✓ Ready in 1965ms\n");
    expect(await watch).toEqual({ ready: false, code: 1 });
  });
});

describe("answers", () => {
  it("is true for a port that replies and false for a free one", async () => {
    const server = createServer((_request, response) => response.end("ok"));
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    const { port } = server.address() as AddressInfo;
    expect(await answers(port)).toBe(true);
    await new Promise<void>((done) => server.close(() => done()));
    expect(await answers(port, "/login", 300)).toBe(false);
  });
});
