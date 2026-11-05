"""Short answers for prompt lines that are not a target — rule-based, no LLM.

Before a run, a line that names no target does not start one: Reconix answers in one or
two sentences and says what to type. A keyword without a target ("scan my network") gets
what that template needs; a question ("what is my api key?") is a question, not a request
for a template, even when it holds a keyword. During a run, a greeting or thanks gets a
friendly line and anything else the usual pointer to the keys. After the run (completed or
stopped) the chat goes on about the same assessment: thanks and greetings get a friendly
line, anything else a pointer to the findings, the report and /new. With the LLM backend
these become the agent's chat replies; the store function names stay.
"""

import re

from .parser import keyword_hint
from .targets import needs

START = ("Type a target to start — a URL, an IPv4 address or range, or a git repo or local "
         "path — or /template to pick a template.")
# Fits every step (a gate still waiting, or a plan running): a typed line decides nothing,
# and commands work in a chat too (a line starting with /).
RUNNING = ("Without a model I can't answer that, and a typed line changes nothing: you "
           "decide with the step's menu. Commands work here too: /findings, /audit, "
           "/report, /status once the plan runs, or /new to start over.")
AFTER_RUN = ("The assessment is finished. With a model set (/model) you can ask about its "
             "findings; otherwise use /findings, /report, or /new to start another.")

NO_MODEL = "No AI model of your own is set: /provider sets one (the Core API uses its own)."
BEFORE_TARGET = ("Ask the model once an assessment has started: before a target, nothing "
                 "you type is sent to it.")

_GREETING = re.compile(r"^\W*(?:hi|hello|hey|hiya|howdy|yo|greetings|"
                       r"good (?:morning|afternoon|evening))\b", re.IGNORECASE)
_THANKS = re.compile(r"\b(?:thanks|thank you|thx|cheers)\b", re.IGNORECASE)
_BYE = re.compile(r"^\W*(?:bye|goodbye|see you|good night)\b", re.IGNORECASE)
# A question: it ends with "?" or starts with a question word ("do" only as "do you/I/we").
_QUESTION = re.compile(r"^\W*(?:what|what's|whats|how|why|is|are|can|could|does|did|should|"
                       r"where|who|whom|whose|which|when|will|would|may|do (?:you|i|we))\b",
                       re.IGNORECASE)
_HELP = re.compile(r"\b(?:help|what can you do|what do you do|who are you|what is reconix|"
                   r"how does (?:this|it) work|how do i|usage)\b", re.IGNORECASE)


def is_question(text: str) -> bool:
    """A line that asks something ("what is my api key?", "how does it work")."""
    text = text.strip()
    return text.endswith("?") or bool(_QUESTION.match(text))


def template_hint(text: str) -> str:
    """The template a line asks for without a target ("scan my network"), or "" (none, or
    the line is a question: it gets an answer, not a template)."""
    return "" if is_question(text) else (keyword_hint(text) or "")


def reply_to(text: str) -> str:
    """The answer to a line that names no target (before a run)."""
    hint = template_hint(text)
    if hint:
        return needs(hint)
    if _BYE.search(text):
        return "Bye! Press Ctrl+Q to quit."
    if _THANKS.search(text):
        return "You're welcome!"
    if _GREETING.search(text):
        return f"Hi! {START}"
    if _HELP.search(text):
        return (f"I run authorized security tests and ask before every risky step. {START} "
                f"{NO_MODEL}")
    if is_question(text):
        from .providers import active_model   # (imported here: this module stays a leaf)

        if active_model() is not None:      # a real model: nothing goes out before a target
            return f"{BEFORE_TARGET} {START}"
        return f"Without a model I can't answer questions. {NO_MODEL} {START}"
    return f"I didn't find a target in that. {START}"


def reply_while_running(text: str) -> str:
    """The answer to a line typed while an assessment runs."""
    if _THANKS.search(text):
        return "You're welcome. The assessment keeps going; /findings shows the findings so far."
    if _GREETING.search(text):
        return ("Hi! The assessment is running. /status shows the live run; /findings, /audit "
                "and /report the rest.")
    return RUNNING


def reply_after_run(text: str) -> str:
    """The answer to a line typed after the assessment finished (completed or stopped)."""
    if _THANKS.search(text):
        return "You're welcome. /findings and /report have everything from this assessment."
    if _GREETING.search(text):
        return ("Hi! This assessment is finished. Use /findings and /report, or set a model "
                "(/model) to ask about its findings.")
    return AFTER_RUN
