from cryptography.fernet import Fernet

from reconix_api.core.config import Settings
from reconix_api.core.disclosure import vault_for_tool_runs


def test_no_fernet_key_keeps_no_values(tmp_path):
    assert vault_for_tool_runs(Settings(fernet_key="", vault_dir=str(tmp_path))) is None


def test_with_a_key_values_are_kept_in_the_vault_folder(tmp_path):
    settings = Settings(fernet_key=Fernet.generate_key().decode(), vault_dir=str(tmp_path))
    vault = vault_for_tool_runs(settings)
    assert vault is not None
    assert vault.folder == tmp_path
