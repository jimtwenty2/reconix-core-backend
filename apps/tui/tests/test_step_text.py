"""A step's content as text (the first reply of "Chat about this") and the plan's tools."""

import pytest

from reconix import store

from .support import run_to

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
    assert "1. Host discovery" in text
    assert "needs your approval" in text


def test_the_approval_text_names_action_and_risk():
    run_to("approval:approval-001")
    text = store.approval_text("approval-001")
    assert store.get_approval("approval-001").action in text
    assert "risk" in text


def test_the_template_text_marks_the_suggestion():
    assert "Network" in store.template_text()


@pytest.mark.parametrize(
    "request_text, row_tools",
    [
        (NETWORK, {"1": "nmap", "2": "nmap, testssl.sh", "3": "nmap"}),
        ("https://shop.example.com", {"1": "OWASP ZAP", "2": "Nuclei, OWASP ZAP"}),
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
