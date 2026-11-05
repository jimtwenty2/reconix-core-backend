"""Flow 0: the first screen, "Which AI model should Reconix use?"."""

from .model import Case, Flow

FLOW = Flow(
    id="PROV",
    number="0",
    title="Set provider (first screen)",
    intro=(
        "Reconix needs the Core API running (./deploy/dev.sh). Every plan, step, finding and "
        "chat answer comes from it; the AI it uses is the one in .env (RECONIX_MODEL_*), "
        "unless you set your own with /provider.",
        'While no model of your own is set, Reconix asks first: "Which AI model should '
        'Reconix use?". Use the Core API\'s model keeps the one in .env; Set a provider… '
        "opens /provider.",
        "Start Reconix with the run-eval script (README-<your OS>.md §2). To see the first "
        "screen again: quit (Ctrl+Q), then start it with --reset (Windows: -Reset). That only "
        "clears ~/.reconix-eval, never your own ~/.reconix; export your /tests results first.",
    ),
    cases=(
        Case(
            "PROV-01",
            "Use the Core API's model",
            (
                "Start Reconix fresh (run-eval with --reset).",
                '"Which AI model should Reconix use?" → Use the Core API\'s model (press '
                "Enter).",
                "Type: who are you?",
            ),
            "The Start screen is ready. The answer comes from the Core API's AI; nothing "
            "starts.",
        ),
        Case(
            "PROV-02",
            "A key is masked",
            (
                "Quit, start Reconix fresh (run-eval with --reset).",
                "Set a provider… → Custom OpenAI-compatible → API key sk-test-0000-1234 → "
                "Save provider.",
                "Type /provider and look at Custom OpenAI-compatible.",
            ),
            "Only sk-…1234 is shown: in the provider list, the form and anywhere else. The full "
            "key never shows.",
        ),
        Case(
            "PROV-03",
            "The question comes back",
            (
                "Quit, start Reconix fresh (run-eval with --reset).",
                "Choose Use the Core API's model.",
                "Quit (Ctrl+Q) and start Reconix again (run-eval, without --reset).",
            ),
            "At the next start Reconix asks again: no model of your own is set.",
        ),
        Case(
            "PROV-04",
            "No question once a model is set",
            ("With a provider set and active, quit and start Reconix again (without --reset).",),
            "No question: the Start screen opens at once and the top bar shows the model.",
        ),
        Case(
            "PROV-05",
            "Unset the provider",
            (
                "/provider → your provider → Unset → Yes, remove it.",
                "Quit and start Reconix again (without --reset).",
            ),
            "The top bar shows llm: off, and at the next start Reconix asks again.",
        ),
    ),
)
