import pytest

from reconix_ai.providers.base_url import BaseUrlError, check_base_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434",
        "http://localhost:11434/",
        "http://ollama:11434",
        "http://[::1]:11434",
        "https://models.example.com",
    ],
)
def test_allowed(url: str) -> None:
    check_base_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5:11434",  # plain http to another computer
        "http://models.example.com",
        "https://169.254.169.254",  # cloud metadata
        "https://metadata.google.internal",
        "https://user:pass@models.example.com",
        "http://127.0.0.1:11434/admin",  # path tricks
        "http://127.0.0.1:11434/?x=1",
        "http://127.0.0.1:11434/#frag",
        "file:///etc/passwd",
        "ftp://127.0.0.1",
        "http://",
        "",
    ],
)
def test_refused(url: str) -> None:
    with pytest.raises(BaseUrlError):
        check_base_url(url)


def test_error_never_repeats_the_address() -> None:
    with pytest.raises(BaseUrlError) as raised:
        check_base_url("https://user:hunter2@models.example.com")

    assert "hunter2" not in str(raised.value)
