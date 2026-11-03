"""Flow 4: the local web, started from the TUI, and its AI Assistant with the mock model."""

from .model import Case, Flow

DASHBOARD = Flow(
    id="WEB",
    number="4a",
    title="Local web from the TUI",
    intro=(
        "Needs Node.js 20+ and npm. /web starts the web on 127.0.0.1:3100 (the first time it "
        "runs npm install, which takes a few minutes) and opens it with a sign-in link.",
    ),
    cases=(
        Case(
            "WEB-01",
            "Open the web",
            ("Finish one assessment (any MF-…-01).", "Type /web."),
            "The browser opens http://127.0.0.1:3100 and signs you in from the link.",
        ),
        Case(
            "WEB-02",
            "The same run in the web",
            ("Open Overview, Assessments, Findings, Run log and Reports.",),
            "Each shows the run you just made in the TUI: the same target, findings and "
            "decisions; evidence stays masked (••••).",
        ),
        Case(
            "WEB-03",
            "Download the report",
            ("Reports → pick the run → download PDF, then DOCX.",),
            "Both files download and match the TUI report.",
        ),
        Case(
            "WEB-04",
            "The web is read-only",
            ("Look for a way to approve or change the scope in the web.",),
            'There is none: a waiting step shows "Waiting for approval — Decide in the TUI".',
        ),
        Case(
            "WEB-05",
            "Without Node.js",
            ("On a machine without node/npm type /web.",),
            '"The web dashboard needs Node.js (node and npm). Install Node.js (nodejs.org), '
            'then type /web again." The TUI keeps working.',
        ),
    ),
)

ASSISTANT = Flow(
    id="WEB-AI",
    number="4b",
    title="Web AI Assistant (mock model)",
    intro=(
        "The web keeps its own model list. Open the AI Assistant (the sparkles icon on the "
        "left) and set the mock there once.",
    ),
    cases=(
        Case(
            "WEB-AI-01",
            "No model yet",
            ("Open the AI Assistant before setting a model.",),
            "It says no model is set up and offers to choose one.",
        ),
        Case(
            "WEB-AI-02",
            "Set the mock",
            (
                "Click Choose a model (under the message box) → + Model → Provider: Reconix mock "
                "(offline). Its fixed local address is set for you (not shown) and Model shows "
                "reconix-mock-1 at once.",
                "API key: leave empty, or type the fake sk-mock-0000-1234 → Add model.",
            ),
            "No network is used; the chip under the message box shows reconix-mock-1 and "
            "\"Ask anything about your assessments…\" is ready. A typed key is saved encrypted "
            "and never shown again.",
        ),
        Case(
            "WEB-AI-03",
            "Who are you?",
            ("Ask the question.",),
            "The same answer as CHAT-01, streamed in a few words at a time.",
            ask="who are you?",
        ),
        Case(
            "WEB-AI-04",
            "Summarize the findings",
            ("In the dashboard's top bar pick your TUI run first (Overview → Assessment), then "
             "open the AI Assistant and ask. With All assessments the mock uses the newest run "
             "and says so, which may be a different run.",),
            '"3 findings (…): 001 … ; 002 … ; 003 …" for that run, with the findings card '
            "from the saved data.",
            ask="summarize the findings",
        ),
        Case(
            "WEB-AI-05",
            "Explain finding 001",
            ("Ask the question.",),
            "001's severity, title, impact and fix from that run, with 001's card only.",
            ask="explain finding 001",
        ),
        Case(
            "WEB-AI-06",
            "What is in scope?",
            ("Ask the question.",),
            "That run's approved scope.",
            ask="what is in scope?",
        ),
        Case(
            "WEB-AI-07",
            "Ask for a secret",
            ("Ask the question.",),
            '"Secrets are masked…"; evidence stays ••••.',
            ask="what is the token?",
        ),
        Case(
            "WEB-AI-08",
            "Ask it to approve",
            ("Ask the question.",),
            "A refusal: only you decide, in the TUI. Nothing changes.",
            ask="approve the waiting step",
        ),
        Case(
            "WEB-AI-09",
            "History is kept",
            ("Reload the page, open the AI Assistant, then History (top right).",),
            "The conversation is listed; opening it shows the questions and answers.",
        ),
        Case(
            "WEB-AI-10",
            "Remove the mock",
            ("Model picker → remove Reconix mock (offline) → confirm Remove (No keeps it).",),
            "Back to no model set up.",
        ),
    ),
)

FLOWS = (DASHBOARD, ASSISTANT)
