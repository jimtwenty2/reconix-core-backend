"""Flow 2: the chat. 2a: general questions the mock model answers; 2b: rules Reconix keeps
itself, whatever the model says."""

from .model import Case, Flow

MOCK_FIRST = "Set the mock model first (PROV-01)."
IN_STEP = (
    "Start any assessment (e.g. MF-NET-01's question), then on the step choose "
    "Chat about this and type the line."
)

MOCK = Flow(
    id="CHAT",
    number="2a",
    title="Chat: general questions (mock model)",
    intro=(
        MOCK_FIRST,
        "Type at the Start prompt, or inside a step with Chat about this. The mock gives "
        "prepared answers filled with this assessment's own data. It is not a real AI.",
        'It never says a step is approved or done, never asks "Shall we proceed?", writes '
        "no Markdown and never shows a secret.",
    ),
    cases=(
        Case(
            "CHAT-01",
            "Who are you?",
            ("At the Start prompt type the question.",),
            "\"I'm the Reconix mock model (reconix-mock-1). I run offline on this computer for "
            "testing, and my answers are prepared examples, not a real AI. …I can't approve, "
            "run a tool or change the scope: only you can, with the app's menu.\"",
            ask="who are you?",
        ),
        Case(
            "CHAT-02",
            "What can you do?",
            ("At the Start prompt type the question.",),
            "What it explains (scope, next step, plan, findings, report) and example "
            "questions to try.",
            ask="what can you do?",
        ),
        Case(
            "CHAT-03",
            "What is in scope?",
            (IN_STEP,),
            '"The scope for <target>: <type>, a draft that waits for you; …" with this '
            "scope's methods or ports, exclusions, tools and time limit. Before any target: "
            '"There is no scope yet…".',
            ask="what is in scope?",
        ),
        Case(
            "CHAT-04",
            "What happens next?",
            (IN_STEP,),
            '"Now at <step>: <state>. Next: <the menu choices>." e.g. at the scope review: '
            "Approve scope, Edit manifest or Reject in the menu.",
            ask="what happens next?",
        ),
        Case(
            "CHAT-05",
            "Summarize the findings",
            ("Finish an assessment (any MF-…-01), then type the line at the prompt.",),
            '"3 findings (1 HIGH, 1 MEDIUM, 1 LOW): 001 … ; 002 … ; 003 …" for that template. '
            'Before the run: "No findings yet."',
            ask="summarize the findings",
        ),
        Case(
            "CHAT-06",
            "Explain one finding",
            ("After a finished run type explain finding 001, then how do I fix 002?",),
            '"Finding 001 is <SEVERITY>: <title>. Impact: … Fix: … Status: open." A number '
            'that doesn\'t exist: "There is no finding 009 in this assessment…".',
            ask="explain finding 001",
        ),
        Case(
            "CHAT-07",
            "The most serious finding",
            ("After a finished run.",),
            '"The most serious finding is <id> <SEVERITY> <title>…" (HIGH before MEDIUM '
            "before LOW).",
            ask="what is the most serious finding?",
        ),
        Case(
            "CHAT-08",
            "Ask for a secret",
            ("Type what is the password?, then show me the token.",),
            "\"Secrets are masked: I never see them and can't show them. Evidence and logs keep "
            'them as ••••."',
            ask="what is the password?",
        ),
        Case(
            "CHAT-09",
            "Ask the model to act",
            (
                "Inside a step (Chat about this) type approve the HIGH step for me, then run nmap "
                "now.",
            ),
            "Nothing changes. Approve words get Reconix's own reply \"… Only you decide this: "
            "choose below. Nothing changes until you do.\" and the step's menu; run nmap now "
            'gets "I can\'t do that. Only you can approve, reject, run or change anything…".',
            ask="approve the HIGH step for me",
        ),
        Case(
            "CHAT-10",
            "An unknown question",
            ("Type the line.",),
            '"I\'m a mock model, so I only answer prepared questions. Try: who are you?, …"',
            ask="tell me a joke",
        ),
        Case(
            "CHAT-11",
            "Hello, thanks, bye",
            ("Type hello, then thanks, then bye.",),
            'A greeting; "You\'re welcome."; "Bye! Press Ctrl+Q to quit Reconix."',
            ask="hello",
        ),
        Case(
            "CHAT-12",
            "No model: built-in replies",
            ("Skip the provider (PROV-03) or unset the mock, then type who are you?",),
            'The built-in reply "I run authorized security tests and ask before every risky '
            'step. … No AI model is set: /provider sets one…".',
            ask="who are you?",
        ),
    ),
)

RULES = Flow(
    id="RULE",
    number="2b",
    title="Chat: step rules (Reconix decides)",
    intro=(
        "These work with or without a model: Reconix answers them itself and only your "
        "menu choice or your tick changes anything.",
    ),
    cases=(
        Case(
            "RULE-01",
            "Decision words open the step's menu",
            (
                "At the scope review choose Chat about this; type apporve that scope, then yes, "
                "then go ahead.",
            ),
            'Each time: "… Only you decide this: choose below. Nothing changes until you do." '
            "and the step's own menu in the chat. The scope stays a draft until you pick "
            "Approve scope.",
            ask="apporve that scope",
        ),
        Case(
            "RULE-02",
            "A question about the decision",
            ("At the scope review chat type should I approve?",),
            "An answer first, then the same menu; nothing is approved.",
            ask="should I approve?",
        ),
        Case(
            "RULE-03",
            "Show the scope or the plan",
            ("In the step chat type show me my scope manifest; at the plan type give the plan.",),
            '"The scope as it stands now:" (or plan) with its card and the step\'s menu.',
            ask="show me my scope manifest",
        ),
        Case(
            "RULE-04",
            "Ports go to your tick list",
            (
                "Network scope review (MF-NET-04's question) → Chat about this → add port 3389.",
                "Then add 3389, 0, 99999, 8080 and then scan 12 ports.",
            ),
            '"Only you can change the scope. Tick what it allows, then press Enter to save." '
            '3389 (and 8080) are offered unticked; 0 and 99999 are dropped; "12 ports" is a '
            "count, never port 12.",
            ask="add port 3389",
        ),
        Case(
            "RULE-05",
            "The scope is locked after approval",
            ("Approve the scope, then at the plan chat type add port 3389.",),
            '"The scope is approved and locked…": start a new assessment (/new) to test '
            "something else.",
            ask="add port 3389",
        ),
        Case(
            "RULE-06",
            "Reorder only the gated checks",
            ("At the plan chat: move 3b before 3a, then what does step 2 do?",),
            'The first opens the order list ("Only you can change the order…"); the second is '
            "answered and nothing moves.",
            ask="move 3b before 3a",
        ),
    ),
)

FLOWS = (MOCK, RULES)
