# Reconix static TUI on Windows 10 / 11

Back to the guide: [README.md](README.md)

## 1. Set up (one time)

You need **git** and **Python 3.9+**. Node.js 20+ with npm is only needed for the local web
(Flow 4).

Use **Windows Terminal** with PowerShell (the old console window draws the screens badly).

```powershell
winget install -e --id Git.Git
winget install -e --id Python.Python.3.12
# optional, for Flow 4:  winget install -e --id OpenJS.NodeJS.LTS
# close and reopen Windows Terminal so the new commands are found
git clone https://github.com/14th-Generation-Advanced-Course/reconix-core-backend.git
cd reconix-core-backend
git checkout sokpiseth/static-ui-parity
powershell -ExecutionPolicy Bypass -File apps\tui\scripts\setup-windows.ps1
```

The script creates `apps/tui/.venv`, installs the TUI into it and checks Node.js. (By hand:
`cd apps\tui; py -m venv .venv; .venv\Scripts\pip install -e .`)

## 2. Start

From the repo folder (`reconix-core-backend`), in Windows Terminal:

```powershell
powershell -ExecutionPolicy Bypass -File apps\tui\scripts\run-eval.ps1          # start
powershell -ExecutionPolicy Bypass -File apps\tui\scripts\run-eval.ps1 -Reset   # start fresh (export /tests results first)
```

- Everything Reconix writes during the test stays in **`$HOME\.reconix-eval`**: assessments,
  the provider and its key, knowledge files, the web assistant and your `/tests` results.
  Your own `$HOME\.reconix` is never read or changed. Reports are saved in `apps\tui\reports\`.
- Use **Windows Terminal**, at least **120 × 40** (maximize the window).
- Without the script (same thing by hand): `cd apps\tui; .venv\Scripts\Activate.ps1; reconix`.
  That uses your normal `$HOME\.reconix` folder.

## 3. First screen: Set provider

While no AI provider is set, Reconix asks **"Set an AI provider?"**:

| Choice | What happens |
|---|---|
| **Use the mock model (offline)** (recommended) | A small form asks for an API key, which is **optional**. Leave it empty, or type a fake one such as `sk-mock-0000-1234` (it is saved encrypted; only `sk-…1234` is ever shown, never the whole key). Then the top bar shows `llm: Reconix mock (offline) · reconix-mock-1 ●`. |
| **Set a provider…** | Opens `/provider` (OpenAI, Anthropic, …). Not needed for this test. |
| **Skip (built-in replies only)** | No model; Reconix asks again at the next start. |

Cases: [FLOW-0-SETUP.md](FLOW-0-SETUP.md).

## 4. Keys you need

| Key | Does |
|---|---|
| Enter | send / choose |
| ↑ ↓ | move in a menu, or go through earlier prompts |
| 1 … 9 | pick a numbered choice in a menu |
| / | the commands (keep typing to filter, Tab completes) |
| ? | the keys for this screen |
| ← → | previous / next screen |
| Ctrl+C | stop a running assessment (it asks first) |
| Ctrl+Q | quit |

## 5. The flows

1. [Flow 0 · Set provider](FLOW-0-SETUP.md)
2. [Flow 1 · Main flow, per template](FLOW-1-MAIN.md): Web URL, API, Network, Source Code
   (5 cases each, every case from the question to the report)
3. [Flow 2 · Chat](FLOW-2-CHAT.md): general questions for the mock model, and step rules
4. [Flow 3 · Commands and settings](FLOW-3-COMMANDS.md)
5. [Flow 4 · Local web and its AI Assistant](FLOW-4-LOCAL-WEB.md)

Mark each case with `/tests` and export your results (`e`): see [README.md](README.md) §3.

## 6. Problems

| Problem | Fix |
|---|---|
| "running scripts is disabled on this system" | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then `.venv\Scripts\Activate.ps1` again |
| `reconix` is not recognized | `.venv\Scripts\Activate.ps1` first (or run `.venv\Scripts\reconix.exe`) |
| The screen looks cut off | make the window bigger (120 × 40 or more) |
| `/web` says it needs Node.js | `winget install -e --id OpenJS.NodeJS.LTS`, reopen the terminal, then `/web` |
| Old runs show up | use the `run-eval` script, or start it with `--reset` (`-Reset` on Windows) |
| Boxes or arrows look broken | use Windows Terminal with a font like Cascadia Mono |
