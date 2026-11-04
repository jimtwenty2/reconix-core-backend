from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from reconix_api.core.interfaces import RiskLevel, ToolName
from reconix_api.models import ScopeManifest, ScopeTarget
from reconix_api.models.enums import ManifestStatus
from reconix_api.schemas.scopes import ScopeDraft, ScopeTargetIn
from reconix_api.services.approvals import snapshot_hash
from reconix_api.services.scopes import next_engagement_code, scope_snapshot, to_approved_scope


def make_manifest(**overrides) -> ScopeManifest:
    values = {
        "manifest_id": uuid4(),
        "assessment_id": uuid4(),
        "version": 1,
        "manifests_status": ManifestStatus.APPROVED,
        "max_risk": RiskLevel.MEDIUM,
        "allowed_tools": ["NMAP", "NUCLEI"],
        "allowed_actions": ["discovery"],
        "allowed_methods": ["GET"],
        "starts_at": None,
        "ends_at": None,
        "limitations": None,
    }
    values.update(overrides)
    return ScopeManifest(**values)


def target(type_: str, value: str, excluded: bool = False) -> ScopeTarget:
    return ScopeTarget(type=type_, value=value, excluded=excluded)


def test_engagement_codes_count_up_per_year():
    assert next_engagement_code(None, 2026) == "RCX-2026-0001"
    assert next_engagement_code("RCX-2026-0041", 2026) == "RCX-2026-0042"


def test_approved_scope_sorts_targets_by_type():
    manifest = make_manifest()
    scope = to_approved_scope(
        manifest,
        [
            target("ip", "172.20.0.5"),
            target("cidr", "172.21.0.0/24"),
            target("domain", "shop.acme.test"),
            target("url", "http://juice-shop:3000/"),
            target("path", "/workspace/code/abc"),
            target("ip", "172.20.0.9", excluded=True),
        ],
    )
    assert scope.assessment_id == manifest.assessment_id
    assert scope.ip_ranges == ["172.20.0.5/32", "172.21.0.0/24"]
    assert scope.domains == ["shop.acme.test"]
    assert scope.url_prefixes == ["http://juice-shop:3000/"]
    assert scope.repo_paths == ["/workspace/code/abc"]
    assert scope.excluded_targets == ["172.20.0.9"]
    assert scope.allowed_tools == [ToolName.NMAP, ToolName.NUCLEI]
    assert scope.max_risk == RiskLevel.MEDIUM


def test_snapshot_hash_ignores_target_order_but_not_content():
    manifest = make_manifest()
    a, b = target("ip", "172.20.0.5"), target("domain", "shop.acme.test")
    first = snapshot_hash(scope_snapshot(manifest, [a, b]))
    assert first == snapshot_hash(scope_snapshot(manifest, [b, a]))
    changed = target("ip", "172.20.0.6")
    assert first != snapshot_hash(scope_snapshot(manifest, [changed, b]))


def test_snapshot_times_are_utc():
    start = datetime(2026, 10, 27, 9, 0, tzinfo=UTC)
    local = make_manifest(starts_at=start.astimezone(timezone(timedelta(hours=7))))
    assert scope_snapshot(local, [])["starts_at"] == start.isoformat()


@pytest.mark.parametrize(
    ("type_", "value"),
    [("ip", "not-an-ip"), ("cidr", "10.0.0.0/99"), ("url", "ftp://x"), ("domain", "a b")],
)
def test_bad_target_values_are_refused(type_, value):
    with pytest.raises(ValidationError):
        ScopeTargetIn(type=type_, value=value)


def test_draft_needs_a_window_in_order():
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        ScopeDraft(
            allowed_tools=[ToolName.NMAP],
            targets=[ScopeTargetIn(type="ip", value="172.20.0.5")],
            starts_at=now,
            ends_at=now - timedelta(hours=1),
        )


def test_draft_takes_any_catalog_tool_and_saves_it_uppercase():
    draft = ScopeDraft(
        allowed_tools=["nmap", "masscan", "zap_scan"],
        targets=[ScopeTargetIn(type="ip", value="172.20.0.5")],
    )
    assert draft.allowed_tools == ["NMAP", "MASSCAN", "ZAP_SCAN"]


def test_draft_refuses_a_tool_outside_the_catalog():
    with pytest.raises(ValidationError):
        ScopeDraft(
            allowed_tools=["not_a_tool"],
            targets=[ScopeTargetIn(type="ip", value="172.20.0.5")],
        )


def test_approved_scope_takes_any_catalog_tool():
    manifest = make_manifest()
    manifest.allowed_tools = ["masscan", "SQLMAP"]
    scope = to_approved_scope(manifest, [target("ip", "172.20.0.5")])
    assert scope.allowed_tools == ["MASSCAN", "SQLMAP"]
