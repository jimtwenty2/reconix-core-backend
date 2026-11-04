#!/usr/bin/env bash
# PreToolUse (Write|Edit|NotebookEdit): never hand-edit generated files, never write a .env or a
# key file. (Staying inside apps/ is stay-in-apps.py's job.)
f=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')
[[ -z "$f" ]] && exit 0

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput: {hookEventName: "PreToolUse",
    permissionDecision: "deny", permissionDecisionReason: $r}}'
  exit 0
}

apps="${CLAUDE_PROJECT_DIR:-$PWD}"
case "$f" in /*) abs="$f" ;; *) abs="$PWD/$f" ;; esac

# Secrets: only .env.example is committed; keys live in ~/.reconix and are never written by hand.
case "$abs" in
  *.env.example) ;;
  */.env|*/.env.*) deny "Never write a .env file. Only .env.example is committed." ;;
  *.key|*.pem) deny "Never write a key file. Keys are created by the app (0600) and never edited." ;;
esac

# Generated files: rerun their script (see the sync-generated skill).
rel="${abs#"$apps"/}"
case "$rel" in
  web/src/styles/tokens.css)
    deny "tokens.css is generated from tui/reconix/theme.py: change the token there, then run 'python scripts/export_tokens.py' in tui/." ;;
  web/src/content/docs/commands.json)
    deny "commands.json is generated from tui/reconix/commands/builtin.py: change COMMANDS, then run 'python scripts/export_commands.py' in tui/." ;;
  web/sample-data/*.json)
    deny "sample-data is generated: change tui/scripts/make_sample_data.py or the store, then run 'python scripts/make_sample_data.py' in tui/." ;;
  web/tests/knowledge-vectors.json)
    deny "knowledge-vectors.json is generated: run 'python scripts/make_knowledge_vectors.py' in tui/." ;;
  web/package-lock.json)
    deny "package-lock.json is written by npm: use 'npm install <pkg>' in web/." ;;
esac
exit 0
