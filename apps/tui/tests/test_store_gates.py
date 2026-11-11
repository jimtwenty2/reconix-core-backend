"""The store is the authority at each gate: template, scope, policy, vault and approvals."""

import dataclasses

import pytest

from reconix import store

from .support import ASK_REQUEST, TEST_PASSWORD, decide, event_kinds, play_until_gate, run_to


def _to_approval(risk: str):
    """Run until the Core API holds a step of `risk` for a decision; its request."""
    run_to("plan")
    decide("plan")
    gate = play_until_gate()
    while gate and store.get_approval(gate.split(":", 1)[1]).risk != risk:
        decide(gate)
        gate = play_until_gate()
    assert gate, f"no {risk} approval"
    return store.get_approval(gate.split(":", 1)[1])


# --- template and scope ------------------------------------------------------------------
def test_template_only_when_asked_and_unknown_ids_are_refused():
    with pytest.raises(store.StoreValidationError):
        store.select_template("web_url")          # the run hasn't asked yet
    run_to("template", ASK_REQUEST)
    with pytest.raises(store.StoreValidationError):
        store.select_template("nope")
    assert store.select_template("web_url").name == "Web URL"


def test_choosing_a_different_template_than_suggested_rebuilds_the_run():
    run_to("template", ASK_REQUEST)               # a bare hostname suggests Web URL
    assert store.select_template("network").name == "Network"
    assert store.get_scope().kind == "network"
    assert store.get_scope().allowed_ports        # network scope carries ports


def test_scope_approval_assigns_the_assessment_id():
    run_to("template", ASK_REQUEST)
    with pytest.raises(store.StoreValidationError):
        store.approve_scope()                     # not asked for yet
    assert store.assessment_label() == ""
    run_to_gate_after_template()
    store.approve_scope()
    assert store.assessment_label() == "RCX-001"
    assert store.is_scope_approved()
    with pytest.raises(store.StoreValidationError):
        store.approve_scope()


def run_to_gate_after_template():
    from .support import play_until_gate
    store.select_template("web_url")
    assert play_until_gate() == "scope"


@pytest.mark.parametrize("method, path, allowed, reason", [
    ("GET", "/products", True, "Within approved scope"),
    ("post", "/search", True, "Within approved scope"),
    ("GET", "/admin", False, "Path outside approved scope"),
    ("GET", "/admin/users", False, "Path outside approved scope"),
    ("GET", "/administrator", True, "Within approved scope"),
    ("DELETE", "/orders/1", False, "Method DELETE not allowed"),
])
def test_policy_check_after_scope_approval(method, path, allowed, reason):
    run_to("account")
    verdict = store.check_request(method, path)
    assert (verdict.allowed, verdict.reason) == (allowed, reason)


def test_policy_blocks_everything_before_the_scope_is_approved():
    verdict = store.check_request("GET", "/products")
    assert not verdict.allowed and verdict.reason == "Scope not approved"


# --- vault -----------------------------------------------------------------------------
def _auth(identity="demo.tester", secret=TEST_PASSWORD):
    return {"identity": identity, "secret": secret}


def test_a_login_is_refused_outside_its_gate():
    run_to("scope")
    with pytest.raises(store.StoreValidationError):
        store.provide_auth(_auth())                   # the run is not asking for one


def test_the_password_never_leaves_the_vault():
    run_to(None)
    shown = [c.text for c in store.list_chat()] + [str(c.rows) for c in store.list_chat()]
    shown += [a.message for a in store.list_activity()]
    shown += [f"{e.kind} {e.detail}" for e in store.list_events()]
    shown += [repr(store.report_data())]
    assert not any(TEST_PASSWORD in text for text in shown)
    assert not any("demo.tester" in text for text in shown)
    from reconix.store import lists
    assert TEST_PASSWORD not in repr(lists.current().vault)


# --- approvals -----------------------------------------------------------------------------
def test_an_approval_is_refused_once_the_run_moved_on():
    medium = _to_approval("MEDIUM")
    store.reject(medium.request_id)
    assert play_until_gate().startswith("approval:")         # now waiting at the HIGH one
    with pytest.raises(store.StoreValidationError):
        store.approve(medium.request_id, command_hash=medium.command_hash)
    with pytest.raises(store.StoreValidationError):
        store.reject(medium.request_id)


def test_medium_needs_the_matching_hash_and_is_decided_once():
    medium = _to_approval("MEDIUM")
    assert not store.needs_confirmation(medium.request_id)
    with pytest.raises(store.StoreValidationError):
        store.approve(medium.request_id, command_hash="sha256:other")
    store.approve(medium.request_id, command_hash=medium.command_hash)
    assert store.is_approved(medium.request_id)
    with pytest.raises(store.StoreValidationError):
        store.reject(medium.request_id)


@pytest.fixture
def high():
    return _to_approval("HIGH")


def test_high_needs_the_double_check_and_the_typed_target(high):
    rid = high.request_id
    assert store.needs_confirmation(rid)
    with pytest.raises(store.StoreValidationError):     # no second confirmation
        store.approve(rid, command_hash=high.command_hash, typed_target=high.target)
    token = store.request_confirmation(rid, high.command_hash)
    with pytest.raises(store.StoreValidationError, match="Type the target"):
        store.approve(rid, command_hash=high.command_hash, confirmation_token=token)
    decision = store.approve(rid, command_hash=high.command_hash, confirmation_token=token,
                             typed_target=high.target)
    assert decision.reason == "" and store.is_approved(rid)
    assert decision.typed_target == high.target and not decision.sent
    assert "Approved: Confirm the login weakness (double-checked)" in [
        e.message for e in store.list_activity()]


def test_a_high_token_works_once_and_only_for_its_hash(high):
    rid = high.request_id
    with pytest.raises(store.StoreValidationError):
        store.request_confirmation(rid, "sha256:other")
    token = store.request_confirmation(rid, high.command_hash)
    with pytest.raises(store.StoreValidationError):
        store.approve(rid, command_hash="sha256:other", confirmation_token=token,
                      typed_target=high.target)
    store.approve(rid, command_hash=high.command_hash, confirmation_token=token,
                  typed_target=high.target)
    with pytest.raises(store.StoreValidationError):
        store.approve(rid, command_hash=high.command_hash, confirmation_token=token,
                      typed_target=high.target)


def test_declining_voids_the_token_and_is_audited(high):
    rid = high.request_id
    token = store.request_confirmation(rid, high.command_hash)
    store.decline_confirmation(rid)
    with pytest.raises(store.StoreValidationError):
        store.approve(rid, command_hash=high.command_hash, confirmation_token=token,
                      typed_target=high.target)
    assert event_kinds()[-2:] == ["approval.confirmation_requested",
                                  "approval.confirmation_declined"]


def test_medium_has_no_confirmation_step():
    medium = _to_approval("MEDIUM")
    with pytest.raises(store.StoreValidationError):
        store.request_confirmation(medium.request_id, medium.command_hash)


# --- editing the scope -----------------------------------------------------------------------
def test_edit_scope_only_while_waiting_and_validates():
    import pytest as _pytest
    from .support import run_to as _run_to
    with _pytest.raises(store.StoreValidationError):
        store.edit_scope(time_limit_minutes=10)       # no scope yet
    _run_to("scope")
    store.edit_scope(allowed_methods=["get", "post"], excluded_paths=["/admin", "/billing"],
                     tools=["Nuclei"], time_limit_minutes=20)
    scope = store.get_scope()
    assert scope.allowed_methods == ["GET", "POST"]        # upper-cased for HTTP
    assert scope.excluded_paths == ["/admin", "/billing"]
    assert scope.time_limit_minutes == 20
    for bad in (dict(time_limit_minutes=999), dict(time_limit_minutes="x"),
                dict(allowed_methods=[]), dict(allowed_methods=["FETCH"]),
                dict(excluded_paths=["admin"]), dict(tools=[])):
        with _pytest.raises(store.StoreValidationError):
            store.edit_scope(**bad)


def test_edit_network_scope_validates_ports():
    from .support import play_until_gate as _p
    store.start_run("scan 10.0.0.0/24 for open ports")
    assert _p() == "scope"                            # the range picked Network
    store.edit_scope(allowed_ports=["80", "443", "8080"])
    assert store.get_scope().allowed_ports == [80, 443, 8080]
    import pytest as _pytest
    with _pytest.raises(store.StoreValidationError):
        store.edit_scope(allowed_ports=["99999"])


def test_a_failed_edit_changes_no_field():
    """All or nothing: a bad field after good ones leaves the whole scope as it was."""
    run_to("scope")
    before = dataclasses.replace(store.get_scope())
    for bad in (dict(allowed_methods=["GET"], time_limit_minutes=9999),
                dict(excluded_paths=["/admin"], tools=["Nuclei", "rm -rf"]),
                dict(tools=["Nuclei"], allowed_ports=["80", "70000"])):
        with pytest.raises(store.StoreValidationError):
            store.edit_scope(**bad)
        assert store.get_scope() == before


@pytest.mark.parametrize("request_text, methods, tools", [
    ("scan 10.0.0.0/24 for open ports", ["tcp CONNECT"], ["NMAP", "testssl"]),
    ("review repo github.com/acme/app", ["READ"], ["semgrep", "Gitleaks", "Trivy"]),
])
def test_edit_checks_methods_and_tools_for_every_kind(request_text, methods, tools):
    from .support import play_until_gate
    store.start_run(request_text)
    assert play_until_gate() == "scope"
    default_tools = list(store.get_scope().tools)
    store.edit_scope(tools=default_tools)                       # the template's own tools pass
    store.edit_scope(allowed_methods=methods, tools=tools)      # named the scope's way
    scope = store.get_scope()
    assert scope.allowed_methods in (["TCP connect"], ["read"])
    assert scope.tools[0] in ("nmap", "Semgrep")
    for bad in (dict(allowed_methods=["DELETE"]), dict(tools=["metasploit"])):
        with pytest.raises(store.StoreValidationError):
            store.edit_scope(**bad)
