#!/usr/bin/env bash
# PreToolUse (Write|Edit): docs/openapi.json is generated from the code, never edited by hand.
f=$(jq -r '.tool_input.file_path // empty')
case "$f" in
  */docs/openapi.json|docs/openapi.json)
    jq -n '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny",
      permissionDecisionReason: "docs/openapi.json is generated. Export it from the FastAPI app instead (see the sync-openapi skill)."}}'
    ;;
esac
exit 0
