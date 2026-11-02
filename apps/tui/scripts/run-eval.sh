#!/usr/bin/env bash
# Start the Reconix static TUI for an evaluation, with every file it writes kept in
# ~/.reconix-eval (assessments, provider keys, knowledge, the web assistant, /tests results),
# so your own ~/.reconix is never read or changed. Linux and macOS.
#   bash apps/tui/scripts/run-eval.sh            start (the first time it asks for a provider)
#   bash apps/tui/scripts/run-eval.sh --reset    delete ~/.reconix-eval first (export /tests results before!)
set -euo pipefail

TUI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVAL="${RECONIX_EVAL_DIR:-$HOME/.reconix-eval}"

if [ "${1:-}" = "--reset" ]; then
    rm -rf -- "$EVAL"
    echo "Removed $EVAL: Reconix starts fresh and asks for a provider again."
fi
if [ ! -x "$TUI_DIR/.venv/bin/reconix" ]; then
    echo "Not set up yet: run  bash apps/tui/scripts/setup-linux.sh  (or setup-macos.sh) first."
    exit 1
fi
mkdir -p "$EVAL" && chmod 700 "$EVAL"

export RECONIX_DATA_DIR="$EVAL/assessments"
export LLM_DB="$EVAL/llm.db"
export LLM_KEY_FILE="$EVAL/llm.key"
export RECONIX_KNOWLEDGE_DIR="$EVAL/knowledge"
export RECONIX_KNOWLEDGE_KEY_FILE="$EVAL/knowledge.key"
export RECONIX_ASSISTANT_DIR="$EVAL/assistant"
export RECONIX_TEST_RESULTS_DIR="$EVAL/test-results"
export RECONIX_WEB_URL_FILE="$EVAL/web.url"
export RECONIX_WEB_LOG="$EVAL/web.log"

cd "$TUI_DIR"                     # reports are saved in apps/tui/reports/
exec "$TUI_DIR/.venv/bin/reconix"
