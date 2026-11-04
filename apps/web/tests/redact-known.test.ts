/* Masking by value (the saved model API keys) and the keyword rules' running time. The shapes
   themselves are checked against the TUI by redact-vectors.json (assistant.test.ts). */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { escapedSecret, MASK, maskValues, redact } from "@/lib/assistant/redact";
import { maskSavedKeys, savedKeys } from "@/lib/assistant/models/known-keys";
import { addProvider } from "@/lib/assistant/models/store";

const MOCK_KEY = "sk-mock-0000-1234"; // the evaluator's mock key: too short for the sk- shape
const saved = { ...process.env };
let root = "";

beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), "reconix-known-test-"));
  process.env = { ...saved, RECONIX_ASSISTANT_DIR: path.join(root, "assistant") };
});
afterEach(() => {
  process.env = { ...saved };
  rmSync(root, { recursive: true, force: true });
});

describe("maskValues", () => {
  it("masks each value as is, longest first, and leaves short ones", () => {
    expect(maskValues("key abcd1234 and abcd", ["abcd", "abcd1234"])).toBe(`key ${MASK} and ${MASK}`);
    expect(maskValues("ab and abc", ["ab", "abc", " "])).toBe("ab and abc");
    expect(maskValues("nothing here", [])).toBe("nothing here");
  });
});

describe("the saved model keys", () => {
  it("are none when nothing is saved", async () => {
    expect(await savedKeys()).toEqual([]);
    expect(await maskSavedKeys(`my key ${MOCK_KEY}`)).toBe(`my key ${MOCK_KEY}`);
  });
  it("are masked by value in a question", async () => {
    await addProvider({ name: "Local", preset: "custom", baseUrl: "http://127.0.0.1:11434/v1", models: ["m"], apiKey: MOCK_KEY });
    expect(redact(`my key ${MOCK_KEY}`)).toContain(MOCK_KEY); // no shape catches it
    const masked = await maskSavedKeys(`my key ${MOCK_KEY} works`);
    expect(masked).toBe(`my key ${MASK} works`);
  });
});

describe("the keyword rules", () => {
  it("treat a tab inside a secret's name as a control character", () => {
    expect(escapedSecret("pass\tword=SECRET1")).toBe(true);
    expect(escapedSecret("name\tvalue")).toBe(false);
  });
  // A rule that may start after every "_" or "-" of a long run and scan the rest is quadratic:
  // these 1 MB runs would take minutes; linear they take well under a second
  it.each(["a_", "a-", "_pass", "pass ", "token is ", "x\t", "DB_PASSWORD"])("run in linear time on a long %j run", (unit) => {
    const text = unit.repeat(Math.floor((1024 * 1024) / unit.length));
    const started = performance.now();
    redact(text);
    expect(performance.now() - started).toBeLessThan(3000);
  });
});
