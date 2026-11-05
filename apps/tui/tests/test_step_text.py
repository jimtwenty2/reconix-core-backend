"""A step's content as text (the first reply of "Chat about this") and the plan's tools."""

import pytest

from reconix import store

from .support import decide, play_until_gate, run_to

NETWORK = "10.0.0.0/24"


def test_the_scope_text_lists_target_ports_and_tools():
    run_to("scope", NETWORK)
    text = store.scope_text()
    assert NETWORK in text and "waits for your approval" in text
    assert "Ports: 22, 80, 443, 8080 and 8443" in text
    assert "nmap" in text and "time limit" in text


def test_the_plan_text_numbers_the_steps_and_marks_the_gates():
    run_to("plan", NETWORK)
    text = store.plan_text()
    assert "1. Find open ports - Start with what is listening. · nmap" in text   # the AI's
    assert "5. Generate report" in text


def test_the_approval_text_names_action_and_risk():
    run_to("plan")
    decide("plan")
    approval_id = play_until_gate().split(":", 1)[1]
    text = store.approval_text(approval_id)
    assert "Approval · Check for known issues · MEDIUM risk" in text
    assert "Purpose: Then look for weaknesses." in text         # the AI's reason
    assert "nothing runs until you approve it" in text


def test_the_template_text_marks_the_suggestion():
    assert "Network" in store.template_text()


@pytest.mark.parametrize(
    "request_text, row_tools",
    [
        (NETWORK, {"1": "nmap"}),                  # NMAP is in a network scope
        ("https://shop.example.com", {"2": "Nuclei"}),  # NUCLEI is in a web scope
    ],
)
def test_plan_rows_show_their_tools(request_text, row_tools):
    run_to("plan", request_text)
    rows = {row.num: row for row in store.plan_overview()}
    for num, tools in row_tools.items():
        assert rows[num].detail.endswith(f" · {tools}")
    tasks = {task.key: task for task in store.plan_tasks()}
    assert not tasks["analysis"].tools and not tasks["report"].tools  # they run no tool


def test_a_tool_removed_from_the_scope_leaves_the_plan():
    run_to("scope", NETWORK)
    store.edit_scope(tools=["nmap"])
    rows = {row.num: row for row in store.plan_overview()}
    assert rows["2"].detail.endswith(" · nmap")
    assert "testssl.sh" not in rows["2"].detail
