import pytest
from pydantic import ValidationError

from reconix_api.core.config import Settings


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_hosts_are_allowed(host):
    assert Settings(host=host).host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::"])  # noqa: S104
def test_api_never_listens_outside_this_computer(host):
    with pytest.raises(ValidationError):
        Settings(host=host)
