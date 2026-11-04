"""Flow 3: commands and settings."""

from .model import Case, Flow

FLOW = Flow(
    id="CMD",
    number="3",
    title="Commands and settings",
    intro=(
        "Type / to see the commands; keep typing to filter, ↑/↓ to pick, Tab to complete, "
        "Enter to run.",
    ),
    cases=(
        Case(
            "CMD-01",
            "Help and the command list",
            ("Press ? on any screen, then Esc.", "Type / then fin, press Tab."),
            "? shows the keys for this screen and the ones that work everywhere. Tab completes "
            "to /findings (or /finding).",
        ),
        Case(
            "CMD-02",
            "Go straight to a template",
            ("Type /template web_url.", "Type https://shop.example.com and press Enter."),
            "The Web URL target prompt opens; the scope draft for that URL follows.",
        ),
        Case(
            "CMD-03",
            "Open the flow screens",
            (
                "During a run type /plan, /approval, /status, /findings, /finding 001, /report.",
                "Press Alt+1 … Alt+8 to jump between the same screens (a bare digit only picks "
                "a menu choice).",
            ),
            "Each command opens that screen; a screen with nothing yet says so.",
        ),
        Case(
            "CMD-04",
            "Export the report",
            (
                "Before the run ends type /export pdf.",
                "After a finished run type /export pdf, /export json, /export docx.",
            ),
            'Before: "The report is available once the assessment is complete." After: '
            '"✓ REPORT SAVED" with "Saved ./reports/<id>.pdf. Open it now?" (the folder is '
            "apps/tui/reports/ when Reconix runs from apps/tui).",
        ),
        Case(
            "CMD-05",
            "Summary, assessments and the audit trail",
            ("Type /summary, /assessments, /audit.",),
            "The summary of this assessment; the list of this session's assessments (Enter "
            "reopens one); the activity log and audit trail with every decision.",
        ),
        Case(
            "CMD-06",
            "Provider list with a masked key",
            ("With the mock set with a fake key (PROV-02) type /provider.",),
            "Reconix mock (offline) [configured] · Reachable · sk-…1234 · reconix-mock-1. The "
            "full key never shows.",
        ),
        Case(
            "CMD-07",
            "Test the mock",
            ("Type /provider test mock.",),
            '"Reconix mock (offline): REACHABLE — reconix-mock-1 (offline)".',
        ),
        Case(
            "CMD-08",
            "Pick the model",
            ("Type /model.",),
            "Reconix mock (offline) · reconix-mock-1 is marked ACTIVE.",
        ),
        Case(
            "CMD-09",
            "A provider that can't be reached",
            (
                "/provider → Custom OpenAI-compatible → Set up → API key sk-test-0000-1234 · "
                "Base URL http://127.0.0.1:9/v1 (nothing listens there) · Model test-model → "
                "Save provider → Yes, test it now.",
                "Afterwards /provider → Custom OpenAI-compatible → Unset → Yes, remove it.",
            ),
            "Only sk-…1234 is shown. The test says UNREACHABLE — connection refused; nothing "
            "leaves this computer and the mock stays the active model.",
        ),
        Case(
            "CMD-10",
            "Add a knowledge file",
            ("Type /add-on and give a local .md or .txt file (e.g. ../../README.md).",),
            "The file is added to the knowledge list; /add-on lists it.",
        ),
        Case(
            "CMD-11",
            "Agent mode needs a real model",
            ("Type /assess 10.0.0.0/24.",),
            '"Agent mode needs a real AI model and the backend harness; the static version '
            'has neither. Nothing runs." Nothing runs.',
            note="Not testable in the static version.",
        ),
        Case(
            "CMD-12",
            "Quit",
            ("Type /quit (or press Ctrl+Q).",),
            "Reconix closes; the assessments are saved for the web (Flow 4).",
        ),
    ),
)
