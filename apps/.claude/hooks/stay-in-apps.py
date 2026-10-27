#!/usr/bin/env python3
"""PreToolUse (Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit|Bash): keep Claude inside apps/.

Claude started in apps/ may read, search, change and run things in apps/ only. Outside it:
- read-only: the repo's AGENTS.md, CLAUDE.md, docs/openapi.json and docs/project-context.md
  (the team rules and the API contract the apps follow);
- read and write: Claude's own plans and memory (~/.claude/plans, ~/.claude/projects/*/memory)
  and its scratchpad (/tmp/claude-<uid>/);
- Bash may also name /dev/null-style devices and programs in /usr/bin, /usr/local/bin, /bin.
Everything else is refused: other team members' parts (services/, deploy/, docs/), the home
folder, the system, and `cd`/`..`/absolute paths that lead out of apps/.

The Bash check reads the command's words (shlex): a word that is an absolute path, starts with
~ or $HOME, or has a `..` part is resolved (following `cd` inside the command) and must stay
inside. A command it cannot read, or a path behind another $VARIABLE, is refused.
"""

import json
import os
import re
import shlex
import sys

# apps/ is found from this file (apps/.claude/hooks/), whatever folder Claude was started in
APPS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
REPO = os.path.dirname(APPS)
HOME = os.path.expanduser("~")
SCRATCH = "/tmp/claude-%d" % os.getuid()

READ_ONLY = {os.path.join(REPO, p) for p in
             ("AGENTS.md", "CLAUDE.md", "docs/openapi.json", "docs/project-context.md")}
CLAUDE_OWN = (os.path.join(HOME, ".claude", "plans"), SCRATCH)
MEMORY = re.compile(re.escape(os.path.join(HOME, ".claude", "projects")) + r"/[^/]+/memory(/|$)")
BASH_EXTRA = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty",
              "/usr/bin", "/usr/local/bin", "/bin")
CD = {"cd", "pushd"}
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "\n"}


def deny(reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))
    sys.exit(0)


def under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def resolve(path: str, cwd: str) -> str:
    """The absolute, normalised path (lexical: `..` is applied, symlinks are not followed)."""
    path = os.path.expanduser(path)
    return os.path.normpath(path if os.path.isabs(path) else os.path.join(cwd, path))


def allowed(path: str, write: bool) -> bool:
    if under(path, APPS) or any(under(path, root) for root in CLAUDE_OWN) or MEMORY.match(path):
        return True
    return not write and path in READ_ONLY


def shown(path: str) -> str:
    return os.path.relpath(path, REPO) if under(path, REPO) else path


# --- file tools ----------------------------------------------------------------------------
def check_file_tool(tool: str, args: dict, cwd: str) -> None:
    write = tool in ("Write", "Edit", "MultiEdit", "NotebookEdit")
    for key in ("file_path", "notebook_path", "path"):
        value = args.get(key)
        if not value:
            continue
        target = resolve(value, cwd)
        # a symlink inside apps/ must not lead out either
        real = os.path.realpath(target) if os.path.lexists(target) else target
        for path in {target, real}:
            if not allowed(path, write):
                verb = "change" if write else "read"
                deny("Stay inside apps/: Claude may not %s %s. Work only in apps/ (the TUI "
                     "and the web); ask the person if something outside is needed."
                     % (verb, shown(path)))
    pattern = args.get("pattern") if tool == "Glob" else None
    if pattern and (pattern.startswith(("/", "~")) or ".." in pattern.split("/")):
        base = re.split(r"[*?\[{]", pattern, maxsplit=1)[0]
        if not allowed(resolve(base or ".", cwd), False):
            deny("Stay inside apps/: the Glob pattern %s reaches outside it." % pattern)


# --- Bash -----------------------------------------------------------------------------------
def words(command: str) -> list:
    command = re.sub(r"\$\{?CLAUDE_PROJECT_DIR\}?", APPS, command)
    command = re.sub(r"\$\{?HOME\}?(?=/|\b)", HOME, command)
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def path_like(word: str) -> bool:
    """A word that can lead out of apps/: `..` in it, ~, or an absolute path on a real top-level
    folder (/etc, /home, /tmp…). "/api/x" in `grep "/api/x"` is a pattern, not a path."""
    if word.startswith("~") or ".." in word.split("/"):
        return True
    top = word.split("/")[1] if word.startswith("/") else ""
    return word == "/" or (bool(top) and os.path.lexists("/" + top))


def check_bash(command: str, cwd: str) -> None:
    try:
        tokens = words(command)
    except ValueError:
        deny("Stay inside apps/: this command could not be checked (unbalanced quotes). Write "
             "files with the Write tool and keep paths relative to apps/.")
    here = cwd
    expect_cd_target = False
    at_command_start = True
    for token in tokens:
        if token in SEPARATORS:
            at_command_start, expect_cd_target = True, False
            continue
        if expect_cd_target:
            expect_cd_target = False
            if token == "-":
                deny("Stay inside apps/: `cd -` can't be checked. cd to a folder inside apps/.")
            target = resolve(token, here)
            if not under(target, APPS) and not under(target, SCRATCH):
                deny("Stay inside apps/: `cd %s` leaves it (%s)." % (token, shown(target)))
            here = target
            continue
        if at_command_start and token in CD:
            expect_cd_target = True
            at_command_start = False
            continue
        if at_command_start and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
            pass                                   # VAR=value before the command: check value
        else:
            at_command_start = False
        for part in [token] + token.split("=", 1)[1:]:
            if "$" in part and "/" in part:
                deny("Stay inside apps/: %s uses a variable, so its path can't be checked. Use a "
                     "path relative to apps/." % part)
            if not path_like(part):
                continue
            target = resolve(part, here)
            if allowed(target, True) or any(under(target, p) for p in BASH_EXTRA):
                continue
            deny("Stay inside apps/: the command reaches %s, outside apps/. Work only in apps/; "
                 "ask the person if something outside is needed." % shown(target))
    if expect_cd_target:                           # a bare `cd` goes home
        deny("Stay inside apps/: a bare `cd` goes to the home folder.")


def main() -> None:
    event = json.load(sys.stdin)
    tool = event.get("tool_name", "")
    args = event.get("tool_input") or {}
    cwd = os.path.realpath(event.get("cwd") or os.getcwd())
    if tool == "Bash":
        if not under(cwd, APPS) and not re.match(r"^\s*cd\s", args.get("command", "")):
            deny("Stay inside apps/: the shell is outside it (%s). Start the command with "
                 "`cd %s`." % (shown(cwd), APPS))
        check_bash(args.get("command", ""), cwd)
    else:
        check_file_tool(tool, args, cwd)


if __name__ == "__main__":
    main()
