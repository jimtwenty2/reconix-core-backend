# Reconix static TUI: evaluator guide

Reconix plans a security test inside a scope **you** approve. This **static** version is a
full simulation: nothing is scanned, no internet is used, and the AI is a built-in **mock
model** (`reconix-mock-1`) that gives prepared answers. The steps, the rules and the approval
gates work as in the real product: the AI suggests, only you decide.

**Flow:** Start → Template → Plan → Approval → Execution → Findings → Finding detail → Report

## 1. Set up and start (pick your system)

| System | Guide | Setup script |
|---|---|---|
| Linux / Kali | [README-LINUX.md](README-LINUX.md) | `apps/tui/scripts/setup-linux.sh` |
| macOS | [README-MACOS.md](README-MACOS.md) | `apps/tui/scripts/setup-macos.sh` |
| Windows 10 / 11 | [README-WINDOWS.md](README-WINDOWS.md) | `apps/tui/scripts/setup-windows.ps1` |

## 2. Test the flows, one at a time

| Flow | Page | Cases |
|---|---|---|
| 0 · Set provider (first screen, mock model) | [FLOW-0-SETUP.md](FLOW-0-SETUP.md) | PROV-01…05 |
| 1 · Main flow, per template: Web URL, API, Network, Source Code | [FLOW-1-MAIN.md](FLOW-1-MAIN.md) | MF-WEB / MF-API / MF-NET / MF-SRC-01…05 |
| 2 · Chat: general questions (mock) and step rules | [FLOW-2-CHAT.md](FLOW-2-CHAT.md) | CHAT-01…12, RULE-01…06 |
| 3 · Commands and settings | [FLOW-3-COMMANDS.md](FLOW-3-COMMANDS.md) | CMD-01…12 |
| 4 · Local web from the TUI and its AI Assistant | [FLOW-4-LOCAL-WEB.md](FLOW-4-LOCAL-WEB.md) | WEB-01…05, WEB-AI-01…10 |

All cases in one table: [TEST-CASES.md](TEST-CASES.md). Things the static version does not
do (don't mark them as failures): [NOT-IN-STATIC.md](NOT-IN-STATIC.md).

## 3. Record your results in the app

Type **`/tests`** on any screen. The checklist lists every flow and case (the same text as
these pages). Move with ↑/↓ and mark the highlighted case:

| Key | Does |
|---|---|
| `p` / `f` / `s` | Pass / Fail / Skip (the same key again clears it) |
| `n` | add a note (a secret typed in a note is masked) |
| `e` | export: `results-<date>.md` and `.json` in `~/.reconix-eval/test-results/` (with the `run-eval` script; else `~/.reconix/test-results/`) |
| `Esc` | back to the app (the assessment is untouched) |

Marks are saved at once, so quitting loses nothing. Send the exported `.md` file back.

## 4. How the target picks the template

| You type | Template |
|---|---|
| A URL `https://…` | Web URL |
| A URL with an API path or word (`/v1`, `/api`, "api", "endpoints", "swagger") | API |
| An IPv4 address or CIDR range (`192.0.2.10`, `10.0.0.0/24`) | Network |
| A git repo (`https://git.example.com/acme/app.git`, `git@host:owner/repo`) or a folder | Source Code |
| A bare hostname (`staging.example.com`) | Reconix asks: "Which kind of target is it?" |

Refused (a message explains, nothing starts): `10.0.0.300`, `10.0.0.0/8` (wider than /16),
dash ranges such as `10.0.0.1-10.0.0.20` (use CIDR), a line over 500 characters.

Use only the example targets in these pages (`example.com` names and documentation
addresses): nothing is ever sent to them.
