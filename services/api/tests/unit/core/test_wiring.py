import pytest

from reconix_api.core.errors import ApiError
from reconix_api.core.wiring import build_interfaces


def test_parts_not_merged_yet_say_so():
    interfaces = build_interfaces()
    with pytest.raises(ApiError) as error:
        interfaces.check(None, None)
    assert error.value.status == 503
    assert error.value.details == {"part": "check"}
