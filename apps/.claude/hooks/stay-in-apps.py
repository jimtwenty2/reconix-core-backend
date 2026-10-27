#!/usr/bin/env python3
"""PreToolUse (Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit|Bash): Claude changes apps/ only.

Claude started in apps/ may:
- read anything in this project (the repo: services/, deploy/, docs/, …) to understand it;
- change things in apps/ only (the TUI and the web);
- read and write its own plans, memory (~/.claude/plans, ~/.claude/projects/*/memory) and
  scratchpad (/tmp/claude-<uid>/).
Nothing outside the project is open, and secret files (.env, *.key, *.pem) are never read.

Bash can read or write with the same words, so a command that touches anything outside apps/
(a path, a `cd`, or a shell already there) must be read-only: only commands from READERS, no
output redirect outside apps/. The check reads the command's words (shlex): a word that is an
absolute path on a real top-level folder, starts with ~ or $HOME, or has a `..` part is resolved
(following `cd` inside the command). A command it cannot read, or a path behind another
$VARIABLE, is refused.
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

CLAUDE_OWN = (os.path.join(HOME, ".claude", "plans"), SCRATCH)
MEMORY = re.compile(re.escape(os.path.join(HOME, ".claude", "projects")) + r"/[^/]+/memory(/|$)")
DEVICES = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty")
PROGRAMS = ("/usr/bin", "/usr/local/bin", "/bin")
SECRET = re.compile(r"(^\.env(\..+)?$|\.key$|\.pem$)")

CD = {"cd", "pushd", "popd"}
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "\n"}
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>"}
# Commands that only read: allowed when a command reaches outside apps/.
READERS = {"cat", "head", "tail", "less", "more", "ls", "tree", "find", "grep", "egrep", "fgrep",
           "rg", "wc", "sort", "uniq", "cut", "tr", "column", "nl", "jq", "diff", "cmp", "file",
           "stat", "du", "realpath", "readlink", "basename", "dirname", "echo", "printf", "pwd",
           "true", "test", "[", "sed", "git", "sha256sum", "md5sum", "cd", "pushd", "popd"}
FIND_WRITES = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0",
               "-fprintf", "-fls"}
GIT_READS = {"log", "show", "diff", "status", "blame", "grep", "ls-files", "ls-tree",
             "rev-parse", "describe", "shortlog", "cat-file", "reflog"}


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


def claude_own(path: str) -> bool:
    return any(under(path, root) for root in CLAUDE_OWN) or bool(MEMORY.match(path))


def can_write(path: str) -> bool:
    return under(path, APPS) or claude_own(path)


def can_read(path: str) -> bool:
    return under(path, REPO) or claude_own(path)


def secret(path: str) -> bool:
    name = os.path.basename(path.rstrip("/"))
    return bool(SECRET.search(name)) and name != ".env.example"


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
        # a symlink must not lead somewhere closed either
        real = os.path.realpath(target) if os.path.lexists(target) else target
        for path in {target, real}:
            if secret(path):
                deny("Never read or write secret files (%s): .env, *.key and *.pem stay "
                     "private. .env.example is fine." % shown(path))
            if write and not can_write(path):
                deny("Claude changes apps/ only: %s is outside it. Reading the rest of the "
                     "project is fine; ask the person to change it." % shown(path))
            if not write and not can_read(path):
                deny("Claude reads this project only: %s is outside it." % shown(path))
    pattern = args.get("pattern") if tool == "Glob" else None
    if pattern and (pattern.startswith(("/", "~")) or ".." in pattern.split("/")):
        base = re.split(r"[*?\[{]", pattern, maxsplit=1)[0]
        if not can_read(resolve(base or ".", cwd)):
            deny("Claude reads this project only: the Glob pattern %s reaches outside it."
                 % pattern)


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


def split_commands(tokens: list) -> list:
    """The simple commands: lists of words, separators dropped."""
    commands, current = [], []
    for token in tokens:
        if token in SEPARATORS:
            if current:
                commands.append(current)
            current = []
        else:
            current.append(token)
    if current:
        commands.append(current)
    return commands


def command_name(command: list) -> tuple:
    """The program a simple command runs and its arguments (VAR=value words skipped)."""
    i = 0
    while i < len(command) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", command[i]):
        i += 1
    return (command[i], command[i + 1:]) if i < len(command) else ("", [])


def read_only(command: list) -> str:
    """'' when the simple command only reads, else why not."""
    name, args = command_name(command)
    if not name:
        return ""
    if name not in READERS:
        return "%s is not a read-only command" % name
    if name == "find" and FIND_WRITES & set(args):
        return "find with %s changes files" % " ".join(sorted(FIND_WRITES & set(args)))
    if name == "sed" and any(a == "-i" or a.startswith(("-i", "--in-place")) for a in args):
        return "sed -i changes files"
    if name in ("grep", "egrep", "fgrep") and any(
            re.match(r"^-[a-zA-Z]*[rR]", a) or a in ("--recursive", "--dereference-recursive")
            for a in args):
        return "grep -r would read .env files too (use the Grep tool, which skips them)"
    if name == "git":
        rest = list(args)
        while rest and rest[0].startswith("-"):           # -C <path>, -c k=v, --no-pager
            flag = rest.pop(0)
            if flag in ("-C", "-c") and rest:
                rest.pop(0)
        sub = rest[0] if rest else ""
        if sub not in GIT_READS:
            return "git %s is not a read-only git command" % sub
    return ""


def check_bash(command: str, cwd: str) -> None:
    try:
        tokens = words(command)
    except ValueError:
        deny("This command could not be checked (unbalanced quotes). Write files with the "
             "Write tool and keep paths relative to apps/.")
    here = cwd
    for command in split_commands(tokens):
        name, args = command_name(command)
        if name in CD:
            if name == "popd" or not args or args[0] == "-":
                deny("`%s` can't be checked. cd to a folder inside the project by name."
                     % " ".join(command))
            target = resolve(args[0], here)
            if not can_read(target):
                deny("`cd %s` leaves the project (%s)." % (args[0], shown(target)))
            here = target
            continue
        # this simple command runs outside apps/, or reaches a path there: it may only read
        outside = not under(here, APPS)
        write_target = False
        for word in command:
            if word in WRITE_REDIRECTS:
                write_target = True
                continue
            if word in (">&", "<&", "<", "<<", "<<<"):
                continue
            for part in [word] + word.split("=", 1)[1:]:
                if "$" in part and "/" in part:
                    deny("%s uses a variable, so its path can't be checked. Use a path relative "
                         "to apps/." % part)
                if secret(part):
                    deny("Never read or write secret files (%s): .env, *.key and *.pem stay "
                         "private." % part)
                if write_target:
                    target = resolve(part, here)
                    if not (can_write(target) or target in DEVICES):
                        deny("Claude changes apps/ only: the command writes %s." % shown(target))
                    continue
                if not path_like(part):
                    continue
                target = resolve(part, here)
                if can_write(target) or any(under(target, p) for p in DEVICES + PROGRAMS):
                    continue
                if can_read(target):
                    outside = True
                    continue
                deny("Claude reads this project only: the command reaches %s." % shown(target))
            write_target = False
        why = read_only(command) if outside else ""
        if why:
            deny("Outside apps/ Claude may only read, and %s. Run it inside apps/, or ask the "
                 "person." % why)


def main() -> None:
    event = json.load(sys.stdin)
    tool = event.get("tool_name", "")
    args = event.get("tool_input") or {}
    cwd = os.path.realpath(event.get("cwd") or os.getcwd())
    if tool == "Bash":
        if not can_read(cwd) and not re.match(r"^\s*cd\s", args.get("command", "")):
            deny("The shell is outside the project (%s). Start the command with `cd %s`."
                 % (cwd, APPS))
        check_bash(args.get("command", ""), cwd)
    else:
        check_file_tool(tool, args, cwd)


if __name__ == "__main__":
    main()
