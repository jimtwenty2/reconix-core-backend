"""deploy/seed.sql loads into the real schema, its approval hashes match what the API
builds, and the API reads its rows back."""

from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import func, select

from reconix_api.models import (
    Action,
    Approval,
    Evidence,
    Finding,
    ScopeManifest,
    ScopeTarget,
    ToolRun,
)
from reconix_api.services.actions import action_hash, to_action
from reconix_api.services.approvals import snapshot_hash
from reconix_api.services.scopes import scope_snapshot
from tests.integration.test_scope_flow import open_session

SEED = Path(__file__).parents[4] / "deploy" / "seed.sql"
ASSESSMENT_ID = "a0000000-0000-4000-8000-000000000001"
MANIFEST_ID = UUID("b0000000-0000-4000-8000-000000000001")


def load_seed(engine) -> None:
    connection = engine.raw_connection()
    try:
        connection.autocommit = True  # the file has its own BEGIN and COMMIT
        connection.cursor().execute(SEED.read_text(encoding="utf-8"))
    finally:
        connection.close()


@pytest.fixture
def seeded(engine, session_factory):
    load_seed(engine)
    return session_factory


def test_the_seed_fills_every_part_of_the_flow(seeded):
    with seeded() as db:
        counts = {
            model.__name__: db.scalar(select(func.count()).select_from(model))
            for model in (ScopeTarget, Action, Approval, ToolRun, Finding, Evidence)
        }
    assert counts == {
        "ScopeTarget": 3,
        "Action": 3,
        "Approval": 3,
        "ToolRun": 2,
        "Finding": 4,
        "Evidence": 3,
    }


def test_the_scope_approval_hash_matches_the_scope(seeded):
    with seeded() as db:
        manifest = db.get(ScopeManifest, MANIFEST_ID)
        targets = db.scalars(select(ScopeTarget).where(ScopeTarget.manifest_id == MANIFEST_ID))
        snapshot = scope_snapshot(manifest, list(targets))
        approval = db.scalar(select(Approval).where(Approval.kind == "scope"))
    assert approval.subject_snapshot == snapshot
    assert approval.subject_hash == snapshot_hash(snapshot)


def test_each_action_approval_hash_matches_its_action(seeded):
    with seeded() as db:
        approvals = db.scalars(select(Approval).where(Approval.kind == "action")).all()
        assert len(approvals) == 2
        for approval in approvals:
            action = to_action(db.get(Action, approval.action_id))
            assert approval.subject_snapshot == action.model_dump(mode="json")
            assert approval.subject_hash == action_hash(action)


def test_the_api_reads_the_seed(seeded, db_client):
    headers = open_session(db_client)

    def get(path: str):
        response = db_client.get(path, headers=headers)
        assert response.status_code == 200, response.json()
        return response.json()

    assessment = get(f"/assessments/{ASSESSMENT_ID}")
    assert assessment["engagement_code"] == "RCX-2026-0001"
    assert assessment["assessment_status"] == "ACTIVE"
    assert get(f"/scope-manifests/{MANIFEST_ID}")["manifests_status"] == "APPROVED"
    actions = get(f"/assessments/{ASSESSMENT_ID}/actions")
    assert sorted(a["tool"] for a in actions) == ["NMAP", "NUCLEI", "ZAP"]
    findings = get(f"/findings?assessment_id={ASSESSMENT_ID}")
    assert {f["severity_status"] for f in findings} == {"HIGH", "MEDIUM", "LOW", "NONE"}
    get(f"/assessments/{ASSESSMENT_ID}/overview")
    get(f"/assessments/{ASSESSMENT_ID}/timeline")
