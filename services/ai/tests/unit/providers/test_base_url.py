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
        "https://llm.example.com/v1",  # where OpenAI-compatible servers answer
        "https://llm.example.com/api/v1",  # a gateway that serves its API under /api
        "https://llm.example.com/api/v1/",
        "http://127.0.0.1:8000/v1/",
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
        "https://llm.example.com/v1/admin",
        "https://llm.example.com/api",  # only /api/v1 itself, nothing near it
        "https://llm.example.com/api/v1/admin",
        "https://llm.example.com/api/v2",
        "https://llm.example.com/x/api/v1",
        "https://llm.example.com/v2",
        "https://llm.example.com/v\t1",  # a tab urlsplit() would drop
        "https://llm.example.com\n/v1",
        "https://metadata.google.internal./",  # trailing dot
        "https://[fd00:ec2::254]/v1",  # AWS IPv6 metadata
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
