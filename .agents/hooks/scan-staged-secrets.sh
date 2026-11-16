#!/usr/bin/env bash
# PreToolUse (Bash: git commit): refuse a commit whose staged changes contain a secret.
cmd=$(jq -r '.tool_input.command // empty')
cd "${PROJECT_DIR:-${CLAUDE_PROJECT_DIR:-.}}" || exit 0

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $r}}'
  exit 0
}

# `git commit -a` stages tracked changes at commit time, so scan those too.
range=(--cached)
[[ "$cmd" =~ (^|[[:space:]])(-a|--all|-[a-zA-Z]*a[a-zA-Z]*)([[:space:]]|$) ]] && range=(HEAD)

files=$(git diff "${range[@]}" --name-only --diff-filter=ACM)
if grep -qE '(^|/)\.env$' <<<"$files"; then
  deny "A .env file is staged. Only .env.example may be committed."
fi

if command -v gitleaks >/dev/null 2>&1; then
  if ! out=$(gitleaks git --pre-commit --staged --no-banner --redact 2>&1); then
    deny "gitleaks found a secret in the staged changes: ${out:0:500}"
  fi
  exit 0
fi

# Fallback when gitleaks is not installed. Lab data and test fixtures hold fake secrets on purpose.
hits=$(git diff "${range[@]}" -U0 -- . ':(exclude)deploy/lab/**' ':(exclude)**/tests/fixtures/**' \
  | grep -E '^\+[^+]' \
  | grep -nE 'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|(password|passwd|secret|api_key|token)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'[:space:]]{8,}' \
  | head -5)
if [[ -n "$hits" ]]; then
  deny "Possible secret in staged changes (mask it or move it to .env): ${hits:0:500}"
fi
exit 0
