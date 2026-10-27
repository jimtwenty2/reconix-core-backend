---
name: write-web-test
description: Patterns for testing the Reconix local web with vitest (lib code and API route handlers) and Playwright (end-to-end on sample-data). Use when writing, fixing or extending tests under web/tests/ or web/e2e/.
---

# Testing the Reconix local web

Run from `web/`: `npm test` (vitest, `tests/**/*.test.ts`), one file `npx vitest run
tests/paging.test.ts`; e2e `npm run build && npm run e2e` (Playwright on `sample-data`, needs a
Chromium). Typecheck first needs `npx next typegen`.

## Unit tests (`tests/`)
- `@/` resolves to `src/`; `server-only` is stubbed (`tests/server-only-stub.ts`).
- Data fixtures: `tests/fixtures.ts` (`SAMPLE_DIR`, `sampleNames()`, `rawSample()`,
  `sampleAssessments()`).
- Shared vectors with the TUI: `redact-vectors.json`, `redact-list-vectors.json`,
  `knowledge-vectors.json` (the last one is generated: `make_knowledge_vectors.py`).

**Lib code**:
```ts
import { describe, expect, it } from "vitest";
import { paginate } from "@/lib/paging";

describe("paginate", () => {
  it("clamps an address value that is out of range", () => {
    expect(paginate(30, "99").page).toBe(3);
  });
});
```

**A route handler** (copy `tests/export-route.test.ts`): mock `next/headers` cookies with a
real session value from `@/lib/auth/session` (`COOKIE`, `sessionValue`), import the handler
after the mocks, then call it with a `Request`. Always test: no session → refused, bad id
(`../../etc/passwd`) → 400, foreign Origin on a change → refused, and that answers are
`no-store`.

## End-to-end (`e2e/`)
- `import { expect, test } from "./fixtures"`; helpers in `e2e/support.ts`: `signIn(page)`,
  `hydrated(page)` (waits for `html[data-hydrated]`), `sample()`, `newest()`, `counted()`.
- Find elements by role and accessible name, or `data-*` hooks; never by class names.
- The model and the knowledge CLI are stand-ins (`e2e/llm-stub.mjs`,
  `e2e/knowledge-cli-stub.mjs`); never call a real model or real Python from e2e.
- Accessibility: `e2e/axe.ts` for new views.

## Rules
- Deterministic: no real network, no wall-clock waits (`expect.poll` / locators' auto-wait).
- A bug fix comes with a test that fails before the fix. Report the real output.
