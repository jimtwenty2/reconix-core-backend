"""A finished validation step judges the finding it hit: the verdict is the AI's, the step
stays COMPLETED whatever the model does, and there is one audit line per verdict."""

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import AgentTask, ApprovedScope, Operator
from reconix_api.findings.shape import NewFinding, dedupe_key
from reconix_api.models import AgentRun as AgentRunRow
from reconix_api.models import Finding, LlmProvider, ValidationRun
from reconix_api.models.enums import (
    AgentRunStatus,
    FindingStatus,
    ProviderType,
    SeverityStatus,
    ValidationStatus,
)
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import llm_providers as provider_repo
from reconix_api.services import findings as findings_service
from reconix_api.services import plans, tool_runs, validation
from reconix_api.services.tool_runs import _without_validated
from tests.fakes import FakeScopes, build_fake_interfaces, fake_mask_secrets

ASSESSMENT = uuid4()
TARGET = "http://juice-shop:3000/rest/user?q=1"
OPERATOR = Operator(session_id=uuid4(), actor="operator")


class _Db:
    """A Session whose only reads are the ones a test was told about, and whose writes go
    straight onto the objects (a fake session never commits)."""

    def __init__(self, committed: list[int] | None = None) -> None:
        self.committed = committed if committed is not None else []

    def commit(self) -> None:
        self.committed.append(1)

    def flush(self) -> None:
        pass

    def add(self, _row) -> None:
        pass

    def rollback(self) -> None:
        pass

    def execute(self, _query):
        return []

    def scalars(self, _query):
        return []

    def scalar(self, _query):
        return None

    def get(self, _model, _key, with_for_update=False):
        return None


@dataclass
class Saved:
    validations: list[ValidationRun] = field(default_factory=list)
    audits: list[tuple[str, dict]] = field(default_factory=list)


def a_finding(code: str = "RCX-009", **changed) -> Finding:
    row = Finding()  # then set: a column's server default leaves its attribute None until save
    row.finding_id = uuid4()
    row.code = code
    row.title = "Reflected cross-site scripting at juice-shop:3000"
    row.target = TARGET
    row.description = "nuclei saw a reflected parameter."
    row.severity_status = SeverityStatus.HIGH
    row.cwe_ids = ["CWE-79"]
    row.owasp_id = ["A03:2021"]
    row.cve_ids = []
    row.validation_status = ValidationStatus.UNCONFIRMED
    row.finding_status = FindingStatus.OPEN
    row.dedupe_key = dedupe_key("nuclei_xss", TARGET)
    row.created_at = datetime.now(UTC)
    row.assessment_id = ASSESSMENT
    for name, value in changed.items():
        setattr(row, name, value)
    return row


def a_run(target: str = TARGET) -> SimpleNamespace:
    """A COMPLETED tool run of a validation step, as the background finds it."""
    return SimpleNamespace(
        tool_run_id=uuid4(),
        action_id=uuid4(),
        tool_run_status="COMPLETED",
        output_masked=f"[POC][V] XSS at {target}",
        target=target,
    )


def a_step(run, purpose: str = "validation") -> SimpleNamespace:
    return SimpleNamespace(action_id=run.action_id, target=run.target, purpose=purpose)


@pytest.fixture
def saved(monkeypatch) -> Saved:
    """The repositories' writes go to a list instead of the database."""
    out = Saved()

    def add(db, row):
        if isinstance(row, ValidationRun):
            # What the insert does: the id, and the columns' server defaults read back.
            row.validation_run_id = uuid4()
            row.created_at = datetime.now(UTC)
            out.validations.append(row)

    monkeypatch.setattr(findings_service.finding_repo, "add", add)
    monkeypatch.setattr(
        findings_service,
        "audit",
        lambda write, kind, operator, assessment_id, details: out.audits.append((kind, details)),
    )
    return out


@pytest.fixture
def interfaces():
    """The fakes, with a scope for the assessment so a verdict can be asked for."""
    fake, parts = build_fake_interfaces()
    scopes = FakeScopes()
    scopes.add(ApprovedScope(assessment_id=ASSESSMENT, max_risk="HIGH"))
    parts["scopes"] = scopes
    fake = replace(fake, get_approved_scope=scopes.get_approved_scope)
    return fake, parts


def wire(monkeypatch, run, awaiting: list[Finding], step=None) -> SimpleNamespace:
    """The run's assessment, the findings still waiting for a verdict, and its action."""
    action = step or a_step(run)
    repo = findings_service.finding_repo
    monkeypatch.setattr(repo, "run_assessment", lambda db, r: ASSESSMENT)
    monkeypatch.setattr(repo, "list_awaiting_validation", lambda db, aid: list(awaiting))
    monkeypatch.setattr(repo, "tool_run_assessment", lambda db, rid: ASSESSMENT)
    monkeypatch.setattr(repo, "get_tool_run", lambda db, rid: run)
    monkeypatch.setattr(
        repo,
        "get",
        lambda db, finding_id, lock=False: next(
            row for row in awaiting if row.finding_id == finding_id
        ),
    )
    provider = LlmProvider(
        llm_provider_id=uuid4(),
        provider_type=ProviderType.RECONIX,
        model_name=None,
        is_active=True,
    )
    monkeypatch.setattr(plans, "approved_scope", lambda i, aid: i.get_approved_scope(aid))
    monkeypatch.setattr(agent_run_repo, "active_provider", lambda db: provider)
    monkeypatch.setattr(provider_repo, "get", lambda db, provider_id: provider)
    # The database, where a new agent run is inserted: it leaves with a uuid and RUNNING.
    saved_run = {"agent_run_id": uuid4(), "agent_runs_status": AgentRunStatus.RUNNING}

    def save_run(db, new_run):
        assert isinstance(new_run, AgentRunRow)
        new_run.__dict__.update(saved_run)

    monkeypatch.setattr(agent_run_repo, "add", save_run)
    monkeypatch.setattr(findings_service.action_repo, "get", lambda db, aid: action)
    return action


async def _down(request, on_piece=None):
    raise ApiError(503, "MODEL_UNAVAILABLE", "The RECONIX model could not answer.")


async def test_a_validation_run_confirms_the_finding_it_hit(monkeypatch, saved, interfaces):
    finding = a_finding()
    run = a_run()
    wire(monkeypatch, run, [finding])
    fake, parts = interfaces
    parts["agent"].verdict = "CONFIRMED"

    results = await findings_service.run_validation(_Db(), fake, fake_mask_secrets, OPERATOR, run)

    assert [result.validation_status for result in results] == [ValidationStatus.CONFIRMED]
    assert finding.validation_status == ValidationStatus.CONFIRMED  # the fake agent's verdict
    [row] = saved.validations
    assert (row.finding_id, row.tool_run_id) == (finding.finding_id, run.tool_run_id)
    assert row.reviewed_by == "agent"  # the verdict is the AI's, never a person's
    assert [kind for kind, _ in saved.audits] == ["FINDING_CHECKED"]  # exactly one line
    [request] = parts["agent"].requests
    assert request.task == AgentTask.VALIDATE
    assert request.tool_results == [run.output_masked]  # the AI reads the run's masked output


async def test_a_run_on_another_target_validates_nothing(monkeypatch, saved, interfaces):
    finding = a_finding(target="10.0.0.5")
    run = a_run("10.0.0.50")  # an adjacent address is not a proof: -pod_targets_finding says no
    wire(monkeypatch, run, [finding])
    fake, parts = interfaces

    results = await findings_service.run_validation(_Db(), fake, fake_mask_secrets, OPERATOR, run)

    assert results == []
    assert saved.validations == [] and saved.audits == []
    assert finding.validation_status == ValidationStatus.UNCONFIRMED
    assert parts["agent"].requests == []  # the AI was never asked


async def test_a_model_that_is_down_leaves_the_finding_as_it_was(
    monkeypatch, saved, interfaces, caplog
):
    finding = a_finding()
    run = a_run()
    wire(monkeypatch, run, [finding])
    fake, _ = interfaces
    fake = replace(fake, ask_agent=_down)

    results = await findings_service.run_validation(_Db(), fake, fake_mask_secrets, OPERATOR, run)

    assert results == []
    assert saved.validations == [] and saved.audits == []
    assert finding.validation_status == ValidationStatus.UNCONFIRMED
    assert "ApiError" in caplog.text  # the error's type, never its text


async def test_a_scan_run_validates_nothing(monkeypatch, saved, interfaces):
    finding = a_finding()
    run = a_run()
    wire(monkeypatch, run, [finding], a_step(run, purpose="scan"))
    fake, parts = interfaces
    repo = SimpleNamespace(completed_step=lambda db, rid: (run, a_step(run, purpose="scan")))
    monkeypatch.setattr(validation, "tool_repo", repo)
    monkeypatch.setattr(findings_service.finding_repo, "add", saved.validations.append)

    verdicts = await validation.validate_in_background(
        _Session, fake, fake_mask_secrets, OPERATOR, run.tool_run_id
    )

    assert verdicts == []
    assert saved.validations == [] and parts["agent"].requests == []


def _Session():  # noqa: N802 - the name a sessionmaker returns
    return _Db()


async def test_a_model_that_is_down_leaves_the_step_completed(monkeypatch, saved, interfaces):
    # The step is a finished tool run; the verdict is asked for afterwards, so a model
    # that cannot answer costs the finding its verdict and the step nothing.
    finding = a_finding()
    run = a_run()
    step = a_step(run)
    wire(monkeypatch, run, [finding], step)
    fake, _ = interfaces
    fake = replace(fake, ask_agent=_down)
    monkeypatch.setattr(
        validation, "tool_repo", SimpleNamespace(completed_step=lambda d, i: (run, step))
    )

    verdicts = await validation.validate_in_background(
        _Session, fake, fake_mask_secrets, OPERATOR, run.tool_run_id
    )

    assert verdicts == []
    assert run.tool_run_status == "COMPLETED"
    assert finding.validation_status == ValidationStatus.UNCONFIRMED
    assert saved.validations == []


# ---------------------------------------------------------------------------
# The step's own output: a duplicate is the finding being validated, not a new one
# ---------------------------------------------------------------------------


def dalfox_item(key: str = "", target: str = TARGET) -> NewFinding:
    return NewFinding(
        title="Reflected cross-site scripting",
        target=target,
        description="dalfox saw a reflected parameter.",
        severity=SeverityStatus.MEDIUM,
        dedupe_key=key or dedupe_key("dalfox_xss", target, "r"),
        cwe_ids=["CWE-79"],
    )


_repo = tool_runs.finding_repo


def _stored(rows: dict[str, Finding]):
    """get_by_dedupe_key over the findings the assessment already has."""

    def get_by_dedupe_key(db, assessment_id, key):
        return rows.get(key)

    return get_by_dedupe_key


def test_a_duplicate_of_the_finding_it_validates_is_not_added(monkeypatch):
    existing = a_finding()
    monkeypatch.setattr(_repo, "get_by_dedupe_key", _stored({existing.dedupe_key: existing}))

    assert _without_validated(None, ASSESSMENT, [dalfox_item(existing.dedupe_key)]) == []


def test_a_validation_steps_new_finding_is_still_saved(monkeypatch):
    monkeypatch.setattr(_repo, "get_by_dedupe_key", _stored({}))

    [item] = _without_validated(None, ASSESSMENT, [dalfox_item()])

    assert item.dedupe_key == dedupe_key("dalfox_xss", TARGET, "r")


def test_a_same_key_on_another_target_is_not_a_duplicate(monkeypatch):
    existing = a_finding()
    monkeypatch.setattr(_repo, "get_by_dedupe_key", _stored({existing.dedupe_key: existing}))

    other = dalfox_item(existing.dedupe_key, target="http://juice-shop:3000/rest/other")
    assert _without_validated(None, ASSESSMENT, [other]) == [other]
