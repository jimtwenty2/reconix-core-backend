"""TEST NOTE — one line of notes for a case in the /tests checklist."""

from typing import Dict, List, Optional

from rich.text import Text

from ... import theme
from ...store import test_guide
from .base import FormField, FormScreen


class TestNoteForm(FormScreen):
    """Dismisses with "saved" once the note is stored (masked), or None."""

    __test__ = False  # not a pytest test class
    CHIP = "Test guide"
    SUBMIT = "Save note"

    def __init__(self, case_id: str, current: str = "") -> None:
        super().__init__()
        self._case_id = case_id
        self._current = current
        self.TITLE = f"NOTE · {case_id}"

    def fields(self) -> List[FormField]:
        return [
            FormField(
                "note",
                "Note (empty clears it)",
                value=self._current,
                placeholder="what you saw, e.g. the message text",
                max_length=test_guide.results.MAX_NOTE,
            )
        ]

    def note(self) -> Optional[Text]:
        return Text("Passwords, tokens and keys in their usual forms are masked before the note "
            "is saved. Don't type a real secret here.", style=theme.MUTED)

    def submit(self, values: Dict[str, str]) -> Optional[str]:
        test_guide.results.set_note(self._case_id, values.get("note", ""))
        return "saved"
