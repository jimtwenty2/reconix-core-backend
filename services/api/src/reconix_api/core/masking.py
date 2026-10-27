"""Secret masking, as the API uses it.

The real function is reconix_ai.harness.mask_secrets (owner: Pojim). Until it is merged,
wiring.py puts a NOT_READY stub here, and tests use the fake in tests/fakes/fake_core.py.
"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request

MaskSecrets = Callable[[str], tuple[str, int]]
"""Text -> (masked text, how many secrets were hidden)."""


def get_mask_secrets(request: Request) -> MaskSecrets:
    return request.app.state.mask_secrets


CurrentMask = Annotated[MaskSecrets, Depends(get_mask_secrets)]
