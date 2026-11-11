import pytest

from reconix_api.core import provider_urls
from reconix_api.core.errors import ApiError


@pytest.mark.parametrize(
    "base_url",
    [
        "https://llm.example.com",
        "https://llm.example.com/",
        "http://127.0.0.1:11434",
        "https://[::1]:8080",
    ],
)
def test_a_plain_safe_address_is_accepted(base_url):
    provider_urls.check(base_url)


@pytest.mark.parametrize(
    "base_url",
    [
        " http://localhost",  # urlsplit() drops the space
        "http://local\thost",  # and the tab
        "http://localhost:80\\evil.com",  # not a port
        "https://llm.example.com:99999",  # a port outside 0-65535
        "https://llm.example.com:0",
        "https://[::1",  # a broken IPv6 host: a 422, not a 500
        "HTTPS://llm.example.com",  # urlsplit() lowercases the scheme
        "http://llm.example.com",  # the AI Service's rule: plain http off this computer
    ],
)
def test_an_address_that_is_not_plain_or_safe_is_refused(base_url):
    with pytest.raises(ApiError) as error:
        provider_urls.check(base_url)
    assert (error.value.status, error.value.code) == (422, "PROVIDER_URL_NOT_ALLOWED")


def test_the_message_never_repeats_the_address():
    with pytest.raises(ApiError) as error:
        provider_urls.check("https://[sk-fake-secret-value]/")
    assert "sk-fake" not in error.value.message


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://localhost:11434", True),
        ("http://127.0.0.1:11434", True),
        ("http://[::1]:11434", True),
        ("http://host.docker.internal:1234/v1", True),  # this computer, from the API container
        ("http://ollama:11434", False),  # a name could resolve anywhere
        ("http://localhost.:11434", False),  # not the exact name
        ("https://gpu.example.com", False),
        ("https://[::1", False),
    ],
)
def test_only_localhost_and_loopback_ips_are_local(url, local):
    assert provider_urls.is_local_address(url) is local
