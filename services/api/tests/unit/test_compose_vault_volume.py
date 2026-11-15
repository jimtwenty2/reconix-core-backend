"""The Compose run must give the disclosure vault a folder it can protect.

Tested from the API suite because the files it checks are the ones that start the API.
Before this, `data/vault` was part of the `../data` host bind mount: a folder on a
Windows mount cannot be made 0700, `DisclosureVault.keep` raised PermissionError, the API
logged "Evidence values not kept" and kept no value, so `GET /evidence/{id}/hidden-values`
was always empty and a `disclosure` approval could never reveal anything.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[4]  # the repo root
VAULT_TARGET = "/app/data/vault"  # RECONIX_VAULT_DIR=data/vault, WORKDIR=/app


def api_volumes() -> list[str]:
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text("utf-8"))
    return [str(item) for item in compose["services"]["api"]["volumes"]]


def declared_volumes() -> list[str]:
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text("utf-8"))
    return [str(name) for name in (compose.get("volumes") or {})]


def test_the_vault_folder_is_a_named_volume_not_the_host_folder():
    vault = [item for item in api_volumes() if item.endswith(f":{VAULT_TARGET}")]
    assert vault == [f"vault-data:{VAULT_TARGET}"], vault


def test_the_vault_volume_is_declared():
    assert "vault-data" in declared_volumes()


def test_the_image_owns_the_vault_folder_for_the_api_user():
    # A new volume takes its owner and rights from this folder in the image; uid 1000 can
    # only chmod a folder it owns, and the harness wants 0700 for the values behind a mask.
    dockerfile = (ROOT / "services" / "api" / "Dockerfile").read_text("utf-8")
    assert f"mkdir -p {VAULT_TARGET}" in dockerfile
    assert f"chmod 700 {VAULT_TARGET}" in dockerfile
    assert "chown -R reconix /app/data" in dockerfile
