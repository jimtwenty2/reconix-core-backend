"""VALIDATE through the real graph: straight to the validate node, with a scripted model."""

from uuid import uuid4

import pytest

from reconix_ai.agent import AgentError, ask_agent
from reconix_ai.contracts import FindingInput
from tests.unit.agent.fakes import FakeModel, Request, make_deps
from tests.unit.analysis.cases import CASES

FTP = CASES[0]


def validate_request(**overrides) -> Request:
    values = {
        "task": "VALIDATE",
        "messages": [],
        "findings": [FindingInput(**FTP.finding)],
        "tool_results": [FTP.output],
    }
    return Request(**(values | overrides))


def verdict(
    status: str = "CONFIRMED", reason: str = "The port answers; the banner matches."
) -> dict:
    return {"verdict": status, "reason": reason}


async def test_the_ai_judges_one_finding_from_the_tool_output(graph) -> None:
    model = FakeModel(verdict("CONFIRMED"))

    result = await ask_agent(graph, validate_request(), str(uuid4()), make_deps(model))

    assert result.validation_status == "CONFIRMED"
    assert result.validation_reason  # a reason is given, and it is the run's text
    assert result.text == result.validation_reason
    assert not result.waiting and result.proposed_action is None
    assert len(model.prompts) == 1  # straight to validate: no understand, find or plan


async def test_two_bad_verdicts_give_a_clear_error(graph) -> None:
    model = FakeModel({"verdict": "MAYBE", "reason": "unsure"}, {"verdict": "nope"})

    with pytest.raises(AgentError) as raised:
        await ask_agent(graph, validate_request(), str(uuid4()), make_deps(model))

    assert raised.value.code == "BAD_MODEL_ANSWER"


async def test_a_secret_in_the_reason_is_masked(graph) -> None:
    model = FakeModel(verdict("CONFIRMED", "Logged in with password=Sup3rS3cretPassw0rd!"))

    result = await ask_agent(graph, validate_request(), str(uuid4()), make_deps(model))

    assert "Sup3rS3cretPassw0rd!" not in result.validation_reason
    assert result.masked_count >= 1


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"findings": []}, "ONE_FINDING"),
        ({"findings": [FindingInput(**FTP.finding)] * 2}, "ONE_FINDING"),
        ({"tool_results": []}, "NO_TOOL_RESULT"),
        ({"tool_results": ["   "]}, "NO_TOOL_RESULT"),
    ],
)
async def test_a_bad_validate_request_never_reaches_the_model(graph, overrides, code) -> None:
    model = FakeModel()

    with pytest.raises(AgentError) as raised:
        await ask_agent(graph, validate_request(**overrides), str(uuid4()), make_deps(model))

    assert raised.value.code == code
    assert model.prompts == []
