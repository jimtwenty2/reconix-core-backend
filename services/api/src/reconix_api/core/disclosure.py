"""The vault that keeps the real values behind masked evidence (harness/disclosure.py).

Values are encrypted with RECONIX_PROVIDER_ENCRYPTION_KEY and kept in RECONIX_VAULT_DIR. A value is
shown only through services/disclosures.py, after a `disclosure` approval.
"""

import logging

from reconix_ai.harness.disclosure import (
    DisclosureError,
    DisclosureVault,
    HiddenValue,
)
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.provider_keys import fernet

# Services and routes import these from here: only core/ imports reconix_ai.
__all__ = [
    "DisclosureError",
    "DisclosureVault",
    "HiddenValue",
    "make_vault",
    "vault_for_tool_runs",
]

logger = logging.getLogger(__name__)


def make_vault(settings: Settings) -> DisclosureVault:
    """For the disclosure endpoints: 503 FERNET_KEY_MISSING or FERNET_KEY_INVALID if unset."""
    return DisclosureVault(settings.vault_dir, fernet(settings))


def vault_for_tool_runs(settings: Settings) -> DisclosureVault | None:
    """For saving evidence. Without a key the evidence is still saved, masked, but its
    values cannot be shown later; a run must never lose its findings for this."""
    try:
        return make_vault(settings)
    except ApiError as error:
        logger.warning("Evidence values are not kept for disclosure: %s", error.code)
        return None
