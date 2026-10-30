"""The real ask_agent on the Postgres checkpointer: a waiting run survives an API restart.

The AI Service is called as a Python package, as the API does it; only the model is scripted.
"""

from datetime import UTC, datetime
from uuid import uuid4

from reconix_ai import agent
from reconix_api.core.agent import make_ask_agent, postgres_graph
from tests.integration.conftest import TEST_DATABASE_URL
from tests.unit.core.test_agent import (
    PLANNED,
    PROVIDER,
    UNDERSTOOD,
    ScriptedModel,
    no_knowledge,
    plan_request,
    resume_of,
)


def make_ask(model: ScriptedModel):
    deps = agent.AgentDeps(
        provider=PROVIDER,
        complete=model.complete,
        search=no_knowledge,
        now=lambda: datetime(2026, 10, 29, 10, tzinfo=UTC),
    )
    return make_ask_agent(postgres_graph(TEST_DATABASE_URL), deps)


async def test_a_waiting_run_resumes_after_a_restart(engine):
    request = plan_request(uuid4())
    planned = await make_ask(ScriptedModel(UNDERSTOOD, PLANNED))(request)

    restarted = make_ask(ScriptedModel())  # a new ask_agent, as after an API restart
    resumed = await restarted(resume_of(request, "APPROVED"))

    assert planned.waiting
    assert planned.checkpoint_id
    assert resumed.agent_run_id == request.agent_run_id
    assert resumed.decision == "APPROVED"
    assert not resumed.waiting
