import pytest

from reconix_api.core.limits import LimitError
from reconix_api.models import Approval
from reconix_api.services.limit_settings import _limit_error, is_limit_change


@pytest.mark.parametrize(
    ("kind", "change", "expected"),
    [
        ("configuration", {"setting": "loop_limits"}, True),
        ("configuration", {"change": "ACTIVATE_LLM_PROVIDER"}, False),
        ("configuration", None, False),
        ("disclosure", {"setting": "loop_limits"}, False),
    ],
)
def test_is_limit_change(kind, change, expected):
    assert is_limit_change(Approval(kind=kind, config_change=change)) is expected


def test_limits_moved_since_is_409_and_bad_values_are_422():
    assert _limit_error(LimitError("LIMITS_CHANGED")).status == 409
    error = _limit_error(LimitError("OUT_OF_RANGE", "max_runs_per_assessment"))
    assert (error.status, error.code) == (422, "OUT_OF_RANGE")
    assert error.details == {"limit": "max_runs_per_assessment"}
