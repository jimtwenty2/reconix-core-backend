"""Evals 20 to 21: questions the agent must answer from its search and its memory.

Eval 20 grounds the answer in the knowledge base; eval 21 in the findings a person
accepted in the fixture session earlier (R2). Both make live model calls, so they
run only with RECONIX_EVALS_MODEL=1 (model calls cost money). Eval 21 additionally
needs one ACTIVE web session whose assessment has a finding (the live fixture).
"""

import os

import pytest

from tests.evals.conftest import Stack


def need_model() -> None:
    if os.environ.get("RECONIX_EVALS_MODEL") != "1":
        pytest.skip("chat evals make live model calls; set RECONIX_EVALS_MODEL=1 to run them")


def test_agent_answers_an_id_question_from_the_knowledge(stack):
    """A Shellshock CVE that is in the corpus (T2 §1) must come back cited."""
    need_model()
    answer = stack.chat("What is CVE-2014-6278 (Shellshock) in one sentence?")
    assert "CVE-2014-6278" in answer


def test_agent_cites_an_accepted_finding_from_memory(stack):
    """A finding accepted in a session is remembered, and a later chat in that session
    cites it. The chat's memory is scoped to the session's own assessment, so the
    fixture session is resumed for its own token and reviewed there."""
    need_model()
    sessions = stack.get("/sessions", interface="web", session_status="ACTIVE")
    fixture = None
    for assessment in stack.get("/assessments"):
        findings = stack.get("/findings", assessment_id=assessment["assessment_id"])
        mine = [s for s in sessions if s["session_id"] == assessment["session_id"]]
        if findings and mine:
            fixture = (mine[0]["session_id"], findings[0])
            break
    if fixture is None:
        pytest.skip("no ACTIVE web session with an assessment that has findings (live fixture)")
    session_id, finding = fixture
    resumed = stack.post(f"/sessions/{session_id}/resume")
    session = Stack(resumed["token"], resumed["session_id"])
    # The person's review, again: accepting a finding writes it to the memory (idempotent).
    session.patch(f"/findings/{finding['finding_id']}", {"finding_status": "OPEN"})
    answer = session.chat(f"Do you remember the finding {finding['code']}? Name its code.")
    assert finding["code"] in answer
