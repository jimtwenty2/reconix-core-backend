#!/usr/bin/env bash
# Reconix static TUI: one-time setup on macOS (Apple silicon or Intel).
# Run from anywhere:  bash apps/tui/scripts/setup-macos.sh
# Creates apps/tui/.venv, installs the TUI into it, and checks Node.js for the local web.
set -euo pipefail

TUI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$TUI_DIR"

say() { printf '\n==> %s\n' "$*"; }

say "Checking Python (3.9 or newer)"
PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
    echo "python3 not found. Install it:  brew install python@3.12   (Homebrew: https://brew.sh)"
    exit 1
fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
    echo "Python $("$PY" -V 2>&1) is too old: Reconix needs 3.9 or newer."
    exit 1
fi
if ! "$PY" -c 'import venv, ensurepip' 2>/dev/null; then
    echo "python3-venv is missing. Reinstall Python:  brew install python@3.12"
    exit 1
fi
echo "OK: $("$PY" -V)"

say "Creating the virtual environment (apps/tui/.venv)"
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/python -m pip install --quiet --upgrade pip
say "Installing the Reconix TUI (a few minutes the first time)"
.venv/bin/python -m pip install --quiet -e .

say "Checking Node.js 20+ and npm (only needed for /web, Flow 4)"
if command -v node >/dev/null && command -v npm >/dev/null; then
    major="$(node -p 'process.versions.node.split(".")[0]')"
    if [ "$major" -ge 20 ]; then
        echo "OK: node $(node -v), npm $(npm -v)"
    else
        echo "WARNING: node $(node -v) is older than 20; /web may not start. The TUI works."
    fi
else
    echo "Not found: the TUI works without it; /web (Flow 4) needs Node.js 20+ and npm."
    echo "Install:  brew install node   (or nvm: https://github.com/nvm-sh/nvm)"
fi

say "Done. Start Reconix for the evaluation (its data stays in ~/.reconix-eval):"
cat <<MSG
    bash apps/tui/scripts/run-eval.sh            (from the repo root; add --reset to start over)
Then type /tests for the checklist. Guide: apps/tui/docs/evaluator/README-MACOS.md
MSG
