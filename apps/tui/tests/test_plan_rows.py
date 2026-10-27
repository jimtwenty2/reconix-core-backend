"""plan_line(): how one plan row is drawn (number, label, command, risk, gate, status)."""

import pytest

from reconix import store
from reconix.models import PlanRow
from reconix.screens.plan import MISSING, plan_line, status_counts

from .support import run_to


def _lines(row: PlanRow, width: int = 0, full: bool = False) -> list:
    return plan_line(row, width, full).plain.split("\n")


def _approval_row() -> PlanRow:
    return PlanRow(
        "3a",
        "Baseline request",
        "read-only check",
        "MEDIUM",
        "approve",
        command="curl -s https://app.example.com/api/orders/10482",
    )


# --- 8, 9: number, label, command or detail ------------------------------------------------
def test_number_label_and_command_are_on_the_first_line():
    first = _lines(_approval_row())[0]
    assert first.startswith(" 3a ") and "Baseline request" in first
    assert "$ curl -s https://app.example.com/api/orders/10482" in first


def test_a_phase_row_shows_what_it_does_instead_of_a_command():
    row = PlanRow("1", "Crawl & map endpoints", "map the permitted surface", "LOW", "auto")
    first = _lines(row)[0]
    assert "map the permitted surface" in first and "$" not in first


# --- 10: risk as colour and text, gate note ----------------------------------------------
@pytest.mark.parametrize("risk", ["LOW", "MEDIUM", "HIGH"])
def test_risk_is_written_out_not_only_coloured(risk):
    row = PlanRow("3a", "Step", "", risk, "approve")
    assert f"● {risk}" in _lines(row)[1]


@pytest.mark.parametrize(
    "gate, note",
    [
        ("auto", "runs automatically"),
        ("login", "asks for the target login"),
        ("approve", "needs your approval"),
    ],
)
def test_each_gate_has_its_note(gate, note):
    assert note in _lines(PlanRow("1", "Step", "", "LOW", gate))[1]


# --- 11: statuses are the store's own --------------------------------------------------------
@pytest.mark.parametrize(
    "status, shown",
    [
        ("pending", "· pending"),
        ("active", "◌ now"),
        ("done", "✓ done"),
        ("rejected", "✕ rejected"),
    ],
)
def test_each_store_status_has_its_label(status, shown):
    assert shown in _lines(PlanRow("1", "Step", "", "LOW", "auto", status))[1]


def test_the_rows_start_with_the_stores_statuses():
    run_to("plan")
    statuses = {row.status for row in store.plan_overview()}
    assert statuses <= {"pending", "active", "done", "rejected"}


def test_an_unknown_status_is_shown_as_it_is_never_as_done():
    second = _lines(PlanRow("1", "Step", "", "LOW", "auto", "queued"))[1]
    assert "queued" in second and "done" not in second


# --- 13: missing values ----------------------------------------------------------------------
def test_missing_values_never_show_none():
    row = PlanRow("", "", "", "", "", "")
    text = plan_line(row, width=80).plain
    assert "None" not in text and text.count(MISSING) >= 4


def test_none_values_are_safe_too():
    row = PlanRow(None, None, None, None, None, None, command=None)
    text = plan_line(row, width=80).plain
    assert "None" not in text


# --- long text: cut with … unless the row is highlighted ---------------------------------------
def test_a_long_command_is_cut_to_the_width():
    row = PlanRow(
        "3a",
        "Step",
        "",
        "HIGH",
        "approve",
        command="sqlmap -u https://app.example.com/" + "x" * 200,
    )
    first = _lines(row, width=76)[0]
    assert len(first) <= 76 and first.endswith("…")


def test_a_long_label_is_cut_inside_its_column():
    row = PlanRow("1", "A very long phase label that goes on and on", "detail", "LOW", "auto")
    first = _lines(row, width=76)[0]
    assert "…" in first and "detail" in first


def test_the_highlighted_row_shows_the_whole_command():
    command = "sqlmap -u https://app.example.com/" + "x" * 200
    row = PlanRow("3a", "Step", "", "HIGH", "approve", command=command)
    assert f"$ {command}" in plan_line(row, width=76, full=True).plain


def test_without_a_width_nothing_is_cut():
    command = "y" * 300
    assert command in plan_line(PlanRow("1", "S", "", "LOW", "auto", command=command)).plain


# --- results summary -----------------------------------------------------------------------
def test_status_counts():
    rows = [
        PlanRow(str(i), "s", "", "LOW", "auto", status)
        for i, status in enumerate(["done", "done", "rejected", "pending", "active"])
    ]
    assert status_counts(rows) == "2 done · 1 rejected · 2 not run"
    assert status_counts(rows[:2]) == "2 done"
