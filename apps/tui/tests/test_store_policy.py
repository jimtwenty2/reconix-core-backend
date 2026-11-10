"""The policy engine: canonical paths, the approved host only, and the time limit."""

from datetime import timedelta

import pytest

from reconix import store
from reconix.models.base import utc_now
from reconix.store import lists

from .support import decide, play_until_gate, run_to

BLOCKED_ADMIN = [
    "/admin", "/Admin", "/ADMIN", "/admin?x=1", "/admin#a", "/./admin", "/foo/../admin",
    "/%61dmin", "/admin;jsessionid=1", "/admin/", "/admin/users",
    "https://staging.example.com/admin", "https://staging.example.com:443/admin",
]
MALFORMED_OR_FOREIGN = [
    "//admin", "admin", "/admin\t", "/%2561dmin", "/a%2fb", "/a%5cb", "/a\\b",
    "https://evil.example.net/x", "http://169.254.169.254/latest",
    "http://staging.example.com/x", "https://staging.example.com:8443/x",
    "https://u:p@staging.example.com/x", "",
]


@pytest.fixture
def approved_scope():
    run_to("plan")          # the scope is approved (on the Core API too); nothing ran yet


@pytest.mark.parametrize("target", BLOCKED_ADMIN)
def test_every_spelling_of_an_excluded_path_is_blocked(approved_scope, target):
    verdict = store.check_request("GET", target)
    assert (verdict.allowed, verdict.reason) == (False, "Path outside approved scope")


@pytest.mark.parametrize("target", MALFORMED_OR_FOREIGN)
def test_ambiguous_or_foreign_targets_are_blocked(approved_scope, target):
    assert not store.check_request("GET", target).allowed


@pytest.mark.parametrize("target", ["/administrator", "/products?id=1", "/api/orders/10482",
                                    "https://staging.example.com/search"])
def test_in_scope_targets_are_allowed(approved_scope, target):
    assert store.check_request("GET", target).allowed


def test_requests_pause_once_the_time_limit_has_passed(approved_scope):
    store.get_scope().time_limit_minutes = 30        # a limit was set on this scope
    lists.current().run.started_at -= timedelta(minutes=31)
    verdict = store.check_request("GET", "/products")
    assert (verdict.allowed, verdict.reason) == (False, "Time limit reached")
    store.approve_more_time()                        # you chose to continue
    assert store.check_request("GET", "/products").allowed


def test_the_run_pauses_when_the_time_limit_has_passed(approved_scope):
    store.get_scope().time_limit_minutes = 30
    decide("plan")
    lists.current().run.started_at -= timedelta(hours=1)
    assert store.advance() is None                   # the run pauses, it does not stop
    assert store.time_limit_pending() and not store.get_run().stopped
    store.stop_for_time()                            # you chose Stop
    assert store.display_phase() == "stopped"
    assert "time limit" in store.get_run().stopped


# --- network targets: one parse, exclusions by meaning -----------------------------------------
def _network_scope_with_exclusions():
    store.start_run("scan 10.0.0.0/24 for open ports")
    assert play_until_gate() == "scope"
    store.edit_scope(allowed_ports=["22", "443"],
                     excluded_paths=["10.0.0.5", "10.0.0.6:22", "10.0.0.16/28"])
    store.approve_scope()


@pytest.mark.parametrize("target", [
    "10.0.0.5:22", "10.0.0.5 :22", "10.0.0.5",            # an excluded host, however written
    "10.0.0.6:22", "10.0.0.6:022",                         # an excluded host:port
    "10.0.0.6:+22", "10.0.0.6:2_2", "10.0.0.6: 22",        # ports int() would accept
    "10.0.0.6:٢٢",                               # non-ASCII digits
    "10.0.0.0/24:22", "10.0.0.0/24",                       # a range is not a host
    "10.0.0.20:22",                                        # inside the excluded /28
    "10.0.0.7:8080", "10.9.9.9:22", "",                    # port, host, nothing
])
def test_network_targets_that_must_be_blocked(target):
    _network_scope_with_exclusions()
    assert not store.check_request("TCP", target).allowed, target


@pytest.mark.parametrize("target", ["10.0.0.6:443", "10.0.0.7:22", "10.0.0.7"])
def test_network_targets_that_stay_allowed(target):
    _network_scope_with_exclusions()
    assert store.check_request("TCP", target).allowed, target


@pytest.mark.parametrize("entry", ["10.0.0.0/33", "10.0.0.5:abc", "10.0.0.5 22", "10.0.0.5:0"])
def test_a_network_exclusion_must_be_readable(entry):
    store.start_run("scan 10.0.0.0/24 for open ports")
    assert play_until_gate() == "scope"
    with pytest.raises(store.StoreValidationError):
        store.edit_scope(excluded_paths=[entry])


# --- source targets: the path that runs must stay in the repository ----------------------------
def _source_scope_approved_here():
    """A source scope, approved in the store only: the Core API can't take one yet (code is
    uploaded through the code-scan flow), but the policy engine still judges its paths."""
    store.start_run("review repo https://git.example.com/acme/app.git")
    assert play_until_gate() == "scope"                # the repo picked Source Code
    lists.current().scope.status = "APPROVED"
    lists.current().run.started_at = utc_now()


def test_a_source_scope_is_approved_and_runs_as_a_code_scan(fake_api):
    store.start_run("review repo https://git.example.com/acme/app.git")
    assert play_until_gate() == "scope"
    store.approve_scope()
    assert store.get_scope().status == "APPROVED"
    assert not any("/scope-manifests" in p for p in fake_api.paths())  # no manifest for source


@pytest.mark.parametrize("target", [
    "../../etc/passwd", "app/../../x", "app\\..\\..\\x", "~/.ssh/id_rsa",
    "https://evil.example.net/x", "C:/Windows/win.ini",
])
def test_a_source_path_that_leaves_the_repository_is_blocked(target):
    _source_scope_approved_here()
    verdict = store.check_request("read", target)
    assert not verdict.allowed and verdict.reason == "Path leaves the repository"


def test_a_source_file_name_with_dots_is_fine():
    _source_scope_approved_here()
    assert store.check_request("read", "app/..hidden/x.py").allowed
