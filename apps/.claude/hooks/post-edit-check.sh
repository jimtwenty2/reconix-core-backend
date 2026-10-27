#!/usr/bin/env bash
# PostToolUse (Write|Edit): check the edited file, and ask for a security review when a file
# that guards scope, approvals or secrets changed.
f=$(jq -r '.tool_input.file_path // .tool_response.filePath // empty')
[[ -z "$f" ]] && exit 0
apps="${CLAUDE_PROJECT_DIR:-$PWD}"

problems=""
case "$f" in
  *.py)
    out=$(python3 -m py_compile "$f" 2>&1) || problems+="$out"$'\n'
    if command -v uvx >/dev/null 2>&1; then
      out=$(uvx ruff check --isolated --no-cache --quiet --line-length 100 --select E,F,W,B \
        --target-version py39 "$f" 2>&1) || problems+="$out"$'\n'
    fi
    ;;
  *.tcss)
    out=$(grep -nE '#[0-9A-Fa-f]{6}\b' "$f") && problems+="Hex colors in TCSS (use \$tokens from theme.CSS_TOKENS):"$'\n'"$out"$'\n'
    ;;
esac
if [[ -n "$problems" ]]; then
  jq -n --arg r "Fix before going on (${f#"$apps"/}):
${problems:0:1500}" '{decision: "block", reason: $r}'
  exit 0
fi

# Safety-relevant files: remind to run the security-reviewer subagent before committing.
case "$f" in
  */store/scope.py|*/store/policy.py|*/store/approvals.py|*/store/vault.py|*/store/redact.py| \
  */store/snapshot.py|*/store/persist.py|*/store/agent_guard.py|*/store/agent_run.py| \
  */store/tools.py|*/llm/guardrail.py|*/llm/crypto.py|*/knowledge/cli.py| \
  */web/src/proxy.ts|*/web/src/lib/auth/*|*/web/src/lib/assistant/redact.ts| \
  */web/src/lib/assistant/context.ts|*/web/src/lib/report/mask.ts|*/web/src/lib/knowledge/cli.ts| \
  */web/src/lib/assistant/models/*|*/web/src/lib/report/pdf.ts)
    jq -n --arg c "${f#"$apps"/} guards scope, approvals, secrets or auth. Before committing, run the security-reviewer subagent on this change and keep its tests green." \
      '{hookSpecificOutput: {hookEventName: "PostToolUse", additionalContext: $c}}'
    ;;
esac
exit 0
