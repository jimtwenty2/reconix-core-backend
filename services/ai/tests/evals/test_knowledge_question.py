"""Eval 20: knowledge-grounded question answering.

The agent must answer a real question from the knowledge it searches, not from its
own memory. One live model call per question, so these run only with
RECONIX_EVALS_MODEL=1 (model calls cost money).
"""

import os

import pytest


def need_model() -> None:
    if os.environ.get("RECONIX_EVALS_MODEL") != "1":
        pytest.skip("chat evals make live model calls; set RECONIX_EVALS_MODEL=1 to run them")


def test_agent_answers_an_id_question_from_the_knowledge(stack):
    """A Shellshock CVE that is in the corpus (T2 §1) must come back cited."""
    need_model()
    answer = stack.chat("What is CVE-2014-6278 (Shellshock) in one sentence?")
    assert "CVE-2014-6278" in answer
