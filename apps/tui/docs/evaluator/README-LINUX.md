# Reconix static TUI on Linux / Kali

Back to the guide: [README.md](README.md)

## 1. Set up (one time)

You need **git** and **Python 3.9+**. Node.js 20+ with npm is only needed for the local web
(Flow 4).

```bash
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip
# optional, for Flow 4:  sudo apt install -y nodejs npm
git clone https://github.com/14th-Generation-Advanced-Course/reconix-core-backend.git
cd reconix-core-backend
git checkout sokpiseth/static-ui-parity
bash apps/tui/scripts/setup-linux.sh
```

The script creates `apps/tui/.venv`, installs the TUI into it and checks Node.js. (By hand:
`cd apps/tui && python3 -m venv .venv && .venv/bin/pip install -e .`)

## 2. Start

From the repo folder (`reconix-core-backend`):

```bash
bash apps/tui/scripts/run-eval.sh            # start Reconix for the evaluation
bash apps/tui/scripts/run-eval.sh --reset    # start completely fresh (first export /tests results)
```

- Everything Reconix writes during the test stays in **`~/.reconix-eval`**: assessments,
  the provider and its key, knowledge files, the web assistant and your `/tests` results.
  Your own `~/.reconix` is never read or changed. Reports are saved in `apps/tui/reports/`.
- Use a terminal of at least **120 × 40** (GNOME Terminal, Konsole, xfce4-terminal or the
  Kali terminal; maximize the window).
- Without the script (same thing by hand): `cd apps/tui && source .venv/bin/activate &&
  reconix`. That uses your normal `~/.reconix` folder.

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
| `python3 -m venv` fails: "ensurepip is not available" | `sudo apt install -y python3-venv` |
| `reconix: command not found` | `source .venv/bin/activate` first (or run `.venv/bin/reconix`) |
| The screen looks cut off | make the window bigger (120 × 40 or more) |
| `/web` says it needs Node.js | `sudo apt install -y nodejs npm` (Node 20+), then `/web` again |
| Old runs show up | use the `run-eval` script, or start it with `--reset` (`-Reset` on Windows) |
