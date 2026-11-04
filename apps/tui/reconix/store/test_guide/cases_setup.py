"""Flow 0: the first screen, "Set an AI provider?" (the offline mock model)."""

from .model import Case, Flow

FLOW = Flow(
    id="PROV",
    number="0",
    title="Set provider (first screen)",
    intro=(
        'While no AI provider is set, Reconix asks first: "Set an AI provider?".',
        "Use the mock model (offline) gives prepared answers on this computer: no key, no "
        "network. Set a provider… opens /provider. Skip starts with built-in replies only.",
        "Start Reconix with the run-eval script (README-<your OS>.md §2). To see the first "
        "screen again: quit (Ctrl+Q), then start it with --reset (Windows: -Reset). That only "
        "clears ~/.reconix-eval, never your own ~/.reconix; export your /tests results first.",
    ),
    cases=(
        Case(
            "PROV-01",
            "Use the mock model without a key",
            (
                "Start Reconix fresh (run-eval with --reset).",
                '"Set an AI provider?" → Use the mock model (offline) (press Enter).',
                "The Reconix mock (offline) form opens: leave API key empty → Save provider.",
            ),
            'A note says "Active model: Reconix mock (offline) · reconix-mock-1". The top bar '
            "shows llm: Reconix mock (offline) · reconix-mock-1 ● (on an 80-column terminal the "
            "short form llm: reconix-mock-1 ●) and the Start screen is ready.",
        ),
        Case(
            "PROV-02",
            "A fake key is masked",
            (
                "Quit, start Reconix fresh (run-eval with --reset).",
                "Use the mock model → API key: sk-mock-0000-1234 → Save provider.",
                "Type /provider and look at Reconix mock (offline).",
            ),
            "Only sk-…1234 is shown: in the provider list, the form and anywhere else. The full "
            "key never shows.",
        ),
        Case(
            "PROV-03",
            "Skip, and the question comes back",
            (
                "Quit, start Reconix fresh (run-eval with --reset).",
                "Choose Skip (built-in replies only).",
                "Type: who are you?",
                "Quit (Ctrl+Q) and start Reconix again (run-eval, without --reset).",
            ),
            'The top bar shows llm: off. The answer is the built-in one and ends with "No AI '
            'model is set: /provider sets one…". At the next start Reconix asks again.',
        ),
        Case(
            "PROV-04",
            "No question once a model is set",
            ("With the mock set (PROV-01), quit and start Reconix again (without --reset).",),
            "No question: the Start screen opens at once and the top bar shows the mock.",
        ),
        Case(
            "PROV-05",
            "Unset the mock",
            (
                "/provider → Reconix mock (offline) → Unset → Yes, remove it.",
                "Quit and start Reconix again (without --reset).",
            ),
            "The top bar shows llm: off, and at the next start Reconix asks again.",
        ),
    ),
)
