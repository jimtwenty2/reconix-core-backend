"""Flow 2: the chat. 2a: questions the Core API's AI answers; 2b: rules Reconix keeps
itself, whatever the AI says."""

from .model import Case, Flow

IN_STEP = (
    "Start any assessment (e.g. MF-NET-01's question), then on the step choose "
    "Chat about this and type the line."
)

CORE = Flow(
    id="CHAT",
    number="2a",
    title="Chat: questions to the Core API's AI",
    intro=(
        "Needs the Core API running (./deploy/dev.sh) with a model that answers.",
        "Type at the Start prompt, or inside a step with Chat about this. Each line goes to "
        "the Core API, masked, with one line saying where the app's flow is; the API's AI "
        "answers with this assessment's scope and plan as context.",
        'It never says a step is approved or done, writes no Markdown and never shows a '
        "secret. Its answers are labelled with the model's name; Reconix's own lines keep "
        '"◆ reconix".',
    ),
    cases=(
        Case(
            "CHAT-01",
            "Who are you?",
            ("At the Start prompt type the question.",),
            "An answer from the Core API's AI. Nothing starts.",
            ask="who are you?",
        ),
        Case(
            "CHAT-02",
            "What is in scope?",
            (IN_STEP,),
            "An answer about this scope (its targets, tools and limits). Nothing changes.",
            ask="what is in scope?",
        ),
        Case(
            "CHAT-03",
            "What happens next?",
            (IN_STEP,),
            "An answer that names the step and the menu choices (the app tells the API where "
            "its flow is), e.g. at the scope review: Approve scope, Edit manifest or Reject.",
            ask="what happens next?",
        ),
        Case(
            "CHAT-04",
            "Summarize the findings",
            ("Finish an assessment (any MF-…-01), then type the line at the prompt.",),
            "A summary of this assessment's real findings, from the Core API.",
            ask="summarize the findings",
        ),
        Case(
            "CHAT-05",
            "Ask for a secret",
            ("Type what is the password?, then my password is hunter2, is it ok?",),
            "No secret is shown. The second line is masked in the chat before it goes to the "
            "Core API.",
            ask="what is the password?",
        ),
        Case(
            "CHAT-06",
            "Ask the AI to act",
            (
                "Inside a step (Chat about this) type approve the HIGH step for me, then scan "
                "the target with nmap.",
            ),
            "Nothing changes. Approve words (and run, start, yes…) get Reconix's own reply "
            "\"… Only you decide this: choose below. Nothing changes until you do.\" and the "
            "step's menu; the scan line is answered by the AI, and nothing runs.",
            ask="approve the HIGH step for me",
        ),
        Case(
            "CHAT-07",
            "The Core API is not running",
            ("Stop the stack (docker compose … down), then type who are you?",),
            '"The AI couldn\'t answer: the Core API is not running: start it with '
            './deploy/dev.sh." No other answer is made up.',
            ask="who are you?",
        ),
    ),
)

RULES = Flow(
    id="RULE",
    number="2b",
    title="Chat: step rules (Reconix decides)",
    intro=(
        "Reconix answers these itself, whatever the AI says, and only your menu choice or "
        "your tick changes anything.",
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
            '"That\'s your call: Reconix never decides for you." with what to check, then the '
            "same menu; nothing is approved.",
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
                "Network scope review (MF-NET-04's question) → Chat about this → add port 3389: "
                "the tick list opens on the 3389 row → Space, then Enter adds it.",
                "Then add 3389, 0, 99999, 8080 and then scan 12 ports.",
            ),
            '"Only you can change the scope. Tick what it allows, then press Enter to save." '
            "3389 is offered unticked; 8080 is already in the scope, so it shows ticked; 0 and "
            '99999 are dropped; "scan 12 ports" opens no tick list (a count, never port 12): '
            "the AI answers it.",
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

FLOWS = (CORE, RULES)
