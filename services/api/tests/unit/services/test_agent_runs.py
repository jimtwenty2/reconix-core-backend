import pytest

from reconix_api.core.errors import ApiError
from reconix_api.models import LlmProvider
from reconix_api.models.enums import ProviderType
from reconix_api.services.agent_runs import active_provider_of


def row(provider_type: ProviderType, is_active: bool) -> LlmProvider:
    return LlmProvider(provider_type=provider_type, model_name="m", is_active=is_active)


def test_a_provider_that_is_no_longer_active_is_never_called():
    """An inactive row can be edited with no approval, e.g. its address pointed elsewhere."""
    with pytest.raises(ApiError) as error:
        active_provider_of(row(ProviderType.OLLAMA, is_active=False))

    assert (error.value.status, error.value.code) == (409, "PROVIDER_CHANGED")


@pytest.mark.parametrize(
    ("provider_type", "is_active"),
    [(ProviderType.OPENAI, True), (ProviderType.RECONIX, False)],
)
def test_the_active_row_and_the_built_in_one_are_used(provider_type, is_active):
    provider = row(provider_type, is_active)

    assert active_provider_of(provider) is provider
