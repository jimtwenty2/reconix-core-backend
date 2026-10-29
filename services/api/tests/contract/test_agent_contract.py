"""The shared agent shapes and the AI Service's own shapes must keep the same field names."""

from dataclasses import fields

import pytest
from pydantic import BaseModel

from reconix_ai import contracts
from reconix_api.core import interfaces

# Shared shape in core/interfaces.py -> the AI Service's shape in reconix_ai/contracts.py
SAME_SHAPES = [
    (interfaces.AgentResponse, contracts.AgentAnswer),
    (interfaces.ChatMessage, contracts.ChatMessage),
    (interfaces.FindingInput, contracts.FindingInput),
    (interfaces.ToolRunInput, contracts.ToolRunInput),
    (interfaces.ReportInput, contracts.ReportInput),
    (interfaces.ResumeInput, contracts.ResumeInput),
    (interfaces.BlockedStep, contracts.BlockedStep),
    (interfaces.FindingAnalysis, contracts.FindingAnalysis),
    (interfaces.PlanStep, contracts.PlanStep),
]


@pytest.mark.parametrize(("shared", "ai"), SAME_SHAPES, ids=lambda shape: shape.__name__)
def test_field_names_match(shared: type[BaseModel], ai: type):
    assert set(shared.model_fields) == {field.name for field in fields(ai)}


def test_a_proposed_action_fits_the_shared_action():
    ai_fields = {field.name for field in fields(contracts.ProposedAction)}

    assert ai_fields <= set(interfaces.Action.model_fields)
    assert "finding_id" not in ai_fields  # the agent can never choose a finding
