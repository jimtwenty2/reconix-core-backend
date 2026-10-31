import pytest

from reconix_ai.knowledge import KnowledgeError
from reconix_ai.providers import ProviderError
from reconix_api.core.errors import ApiError
from reconix_api.core.knowledge_add_ons import api_errors


def status_of(error: Exception) -> tuple[int, str]:
    with pytest.raises(ApiError) as raised, api_errors():
        raise error
    return raised.value.status, raised.value.code


def test_qdrant_down_is_503():
    assert status_of(KnowledgeError("KNOWLEDGE_UNAVAILABLE", "down")) == (
        503,
        "KNOWLEDGE_UNAVAILABLE",
    )


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("MODEL_UNAVAILABLE", 503),
        ("PROVIDER_URL_NOT_ALLOWED", 422),
        ("EMPTY_RESPONSE", 502),  # any other model failure, as for the agent
    ],
)
def test_a_model_error_gets_the_agent_status(code, status):
    assert status_of(ProviderError(code, "failed")) == (status, code)


def test_other_errors_pass_through():
    with pytest.raises(ValueError), api_errors():
        raise ValueError("a bug")
