import pytest

from reconix_api.core import provider_checks
from reconix_api.core.errors import ApiError


@pytest.mark.parametrize("url", ["http://10.0.0.5:11434", "http://169.254.169.254"])
async def test_models_are_never_asked_off_this_computer(url):
    with pytest.raises(ApiError) as raised:
        await provider_checks.local_models(url)
    assert raised.value.code == "PROVIDER_URL_NOT_ALLOWED"


async def test_an_ollama_that_does_not_answer_is_503():
    with pytest.raises(ApiError) as raised:
        await provider_checks.local_models("http://127.0.0.1:1")  # nothing listens on port 1
    assert (raised.value.status, raised.value.code) == (503, "MODEL_UNAVAILABLE")
