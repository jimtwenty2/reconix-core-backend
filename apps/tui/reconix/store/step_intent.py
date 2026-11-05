"""A line in the step chat that makes the step's decision ("approve that scope", "yes").

Only the operator moves the flow, and only with the step's menu. No model is asked: a plain
word check spots the decision, Reconix says nothing has changed yet, and the step chat
shows the step's own menu (the same choices, the same handlers). A question about the
decision ("should I approve?") is answered first, then the menu follows. Typos in the long
verbs count ("apporve"), so a misspelt decision never reaches the model either. Asking to
see the scope or the plan shows its card (never the model's list).
"""

import difflib
import re
from typing import List

from .progress import step_status
from .transcript import add_chat

# Verbs long enough to match with typos; short go-ahead words only match exactly.
VERBS = ["approve", "accept", "confirm", "reject", "execute", "proceed", "continue"]
SHORT_VERBS = {"run", "start", "go", "decline", "deny"}
GO_AHEAD = {
    "yes",
    "y",
    "yep",
    "yeah",
    "ok",
    "okay",
    "sure",
    "go",
    "go ahead",
    "proceed",
    "continue",
    "do it",
    "start",
    "let's go",
    "lets go",
    "next",
    "approve",
    "run",
}
QUESTION_WORDS = (
    "should",
    "can",
    "could",
    "is",
    "are",
    "what",
    "why",
    "how",
    "when",
    "do",
    "does",
    "will",
    "would",
    "which",
)
_WORD = re.compile(r"[a-z']+")
_VIEW = re.compile(
    r"^(?:please\s+)?(?:show|see|view|print|display|give|list|what(?:'s| is)|where(?:'s| is))?"
    r"\s*(?:me\s+|us\s+)?(?:the\s+|my\s+|this\s+|our\s+)?(?:current\s+|test\s+)?"
    r"(scope|plan)(?:\s+manifest)?\s*(?:again|now|please)?\s*[?.!]*$",
    re.IGNORECASE,
)

NOTHING_YET = "Only you decide this: choose below. Nothing changes until you do."


def _words(text: str) -> List[str]:
    return _WORD.findall(text.casefold())


def _has_verb(text: str) -> bool:
    for word in _words(text):
        if word in SHORT_VERBS or difflib.get_close_matches(word, VERBS, n=1, cutoff=0.8):
            return True
    return False


def _is_question(text: str) -> bool:
    words = _words(text)
    return text.rstrip().endswith("?") or bool(words and words[0] in QUESTION_WORDS)


def wants_decision(text: str) -> bool:
    """A line that makes the decision itself: "yes", "go ahead", "apporve that scope"."""
    line = " ".join(_words(text))
    if line in GO_AHEAD:
        return True
    return _has_verb(text) and not _is_question(text)


def asks_about_decision(text: str) -> bool:
    """A question about the decision ("should I approve it?"): answer it, then the menu."""
    return _has_verb(text) and _is_question(text)


# A request to change the plan itself (not the scope): add/remove/change a step or phase,
# focus somewhere, re-plan. Scope-level words (a tool or port) are handled by wants_scope_change
# first, so this is for plan wording and emphasis the AI can re-draft within the same scope.
_PLAN_CHANGE_VERB = (
    "add", "remove", "drop", "change", "edit", "replace", "include", "skip", "focus",
    "prioriti", "redraft", "re-draft", "redo", "replan", "re-plan", "another", "more",
    "different", "instead", "also",
)
_PLAN_CHANGE_NOUN = ("step", "steps", "plan", "phase", "phases", "scan", "check", "test",
                     "coverage", "stage")


def wants_plan_change(text: str) -> bool:
    """A line asking to change the test plan (add/change a step, focus somewhere, re-plan):
    the AI re-drafts the plan and you review it. Only meaningful at the Plan step."""
    low = text.casefold()
    if not any(noun in low for noun in _PLAN_CHANGE_NOUN):
        return False
    return (any(verb in low for verb in _PLAN_CHANGE_VERB)
            or (_is_question(text) and ("plan" in low or "step" in low)))


def wants_view(text: str) -> str:
    """"show the scope", "give the plan": "scope" or "plan" (its card, then the menu)."""
    match = _VIEW.match(text.strip())
    return match.group(1).casefold() if match else ""


def decision_reply() -> str:
    """Reconix's own line before the menu (recorded, so the model's history has it too)."""
    status = step_status()
    state = status.state[0].upper() + status.state[1:]
    if status.pending:
        text = f"{state}. {NOTHING_YET}"
    else:
        text = f"{state}. Nothing waits for your decision here: {status.choices}."
    add_chat("text", "reconix", text)
    return text


def view_reply(view: str) -> str:
    """Reconix's line before the scope or plan card ("The scope as it stands now:"),
    recorded like any other reply, so the chat's last exchange and the model's history
    have it."""
    if view not in ("scope", "plan"):
        raise ValueError(f"No card for {view!r}.")
    text = f"The {view} as it stands now:"
    add_chat("text", "reconix", text)
    return text
