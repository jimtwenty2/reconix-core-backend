# AGENTS.md — Local web (Next.js, xterm.js)

Owner: Sokpiseth

Read the root `AGENTS.md` first. These rules add to it.

Scope: Talks only to the local Core API.

## Folders

| Folder | Holds |
|---|---|
| `src/app/` | pages: overview, assistant, assessments, findings, scope, report, terminal, docs |
| `src/components/` | shared UI components |
| `src/content/` | short in-app docs text |
| `src/lib/api/` | types generated from `docs/openapi.json`, fake API reading `../sample-data` |
| `src/lib/auth/` | token from the `/web` link, kept in memory only |
| `src/styles/` | styles |
| `scripts/` | `gen-api-types` (openapi-typescript) |
| `tests/` | `unit/`, `e2e/` (Playwright, viewer and operator) |

## Rules

- Call only the local Core API. No other servers, no direct calls to the AI Service or the Kali container.
- API types are generated (`npm run gen-api-types`); never hand-write or edit them.
- The sign-in token lives in memory only: never in `localStorage`, cookies or URLs after sign-in.
- A **viewer** sees no buttons that change data. The API enforces it too; the e2e tests cover both roles.
- The Terminal page opens the TUI over the API WebSocket and is for operators only.
- Show masked values as the API returns them; never try to unmask on the client.

## Done when

`npm run lint && npm run test` pass, and the Playwright tests pass for both viewer and operator.

<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
