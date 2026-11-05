#!/usr/bin/env bash
# PreToolUse (Bash): never change the Main branch. Main only moves through a reviewed PR that
# a person merges. Develop is open to commit, push and merge (force-push is denied in
# settings.json). The deny rules there block commands that name Main; this hook blocks:
#   - commands that would change Main because it is the branch checked out right now;
#   - `gh pr merge` of a PR whose base is Main.
if ! command -v jq >/dev/null; then
  echo "protect-main.sh needs jq on the PATH" >&2
  exit 2 # blocks the command; install jq to continue
fi
cmd=$(jq -r '.tool_input.command // empty')

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput: {hookEventName: "PreToolUse",
    permissionDecision: "deny", permissionDecisionReason: $r}}'
  exit 0
}

# Only a command that is run counts: at the start of a line, or after ; & | or (. Text that
# merely mentions it (a commit message, a quoted string, a grep pattern) does not.
runs() {
  printf '%s\n' "$cmd" | grep -Eq "(^|[;&|(])[[:space:]]*($1)([[:space:]]|$)"
}

if runs "gh pr merge"; then
  # The PR number or branch is the first argument after "merge" that is not a flag.
  pr=$(printf '%s\n' "$cmd" | grep -Eo "gh pr merge[^;&|]*" | head -1 | cut -d' ' -f4- |
    tr ' ' '\n' | grep -v '^-' | grep -m1 .)
  base=$(cd "$CLAUDE_PROJECT_DIR" && gh pr view $pr --json baseRefName -q .baseRefName 2>/dev/null)
  if [ -z "$base" ]; then
    deny "Could not read this PR's base branch, so it may be Main. Check it with gh pr view and merge it yourself."
  fi
  if [ "$base" = "Main" ]; then
    deny "This PR merges into Main. Claude never merges into Main; a person does it on GitHub."
  fi
fi

if runs "git ((-C|-c) [^ ]+ )*(commit|merge|rebase|reset|cherry-pick|revert|am|pull|push|stash pop|stash apply)"; then
  branch=$(git -C "$CLAUDE_PROJECT_DIR" branch --show-current 2>/dev/null)
  if [ "$branch" = "Main" ]; then
    deny "You are on Main. Never change Main: switch to Develop (or a feat/, fix/ or chore/ branch) first."
  fi
fi
exit 0
