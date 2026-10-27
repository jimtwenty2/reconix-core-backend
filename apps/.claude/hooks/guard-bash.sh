#!/usr/bin/env bash
# PreToolUse (Bash): refuse real scanners, risky git, and reading secrets.
cmd=$(jq -r '.tool_input.command // empty')
[[ -z "$cmd" ]] && exit 0

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput: {hookEventName: "PreToolUse",
    permissionDecision: "deny", permissionDecisionReason: $r}}'
  exit 0
}

# A word that starts a command: the start, or after ; & | ( ` $( or sudo/env/exec.
start='(^|[;&|(`]|\$\(|[[:space:]](sudo|env|exec|xargs|nohup|timeout [0-9]+))[[:space:]]*'

# Real scanners and attack tools never run from the apps: the backend runs them in the Kali
# container, inside the approved scope, after a person approves.
scanners='nmap|masscan|rustscan|nuclei|nikto|sqlmap|zap(\.sh|-cli)?|zaproxy|gobuster|ffuf|dirb|dirsearch|wfuzz|hydra|medusa|metasploit|msfconsole|msfvenom|wpscan|whatweb|amass|subfinder|naabu|httpx-toolkit'
if [[ "$cmd" =~ $start($scanners)([[:space:]]|$) ]]; then
  deny "Never run a scanner (${BASH_REMATCH[3]}) from the apps. Scans run in the backend's Kali container, inside the approved scope, after human approval."
fi

# Git: work goes through a branch and a pull request.
if [[ "$cmd" =~ git[[:space:]]+push ]]; then
  [[ "$cmd" =~ (--force|[[:space:]]-f([[:space:]]|$)|--force-with-lease) ]] \
    && deny "No force push. Push a new commit instead."
  [[ "$cmd" =~ git[[:space:]]+push.*[[:space:]:](main|Main|Develop)([[:space:]]|$) ]] \
    && deny "Nobody pushes to main or Develop directly. Push your <name>/<task> branch and open a pull request."
fi
[[ "$cmd" =~ git[[:space:]].*--no-verify ]] && deny "Don't skip the git hooks (--no-verify)."
[[ "$cmd" =~ git[[:space:]]+(reset[[:space:]]+--hard|clean[[:space:]]+-[a-zA-Z]*f) ]] \
  && deny "This discards work. Ask the person first."

# Secrets: .env and the app's key files are never read or printed.
if [[ "$cmd" =~ (cat|less|more|head|tail|strings|xxd|od|base64|cp|scp)[[:space:]].*(\.env([[:space:]]|$|[^.a-z])|\.key([[:space:]]|$)|\.pem([[:space:]]|$)|\.reconix/[a-z.]*key) ]]; then
  deny "Never read .env or key files (~/.reconix/*.key, models.key, knowledge.key)."
fi
exit 0
