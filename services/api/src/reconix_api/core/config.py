"""Settings, read from the environment or .env (prefix RECONIX_)."""

import ipaddress
from functools import lru_cache
from typing import Annotated, Self

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    # populate_by_name: a field with an env alias can still be set by its name in code.
    model_config = SettingsConfigDict(
        env_prefix="RECONIX_", env_file=".env", extra="ignore", populate_by_name=True
    )

    # The API only ever listens on this computer. Inside its Docker container it listens on
    # 0.0.0.0 instead, and Compose publishes the port on 127.0.0.1 only (S10). Only the
    # Compose api service sets in_container (RECONIX_IN_CONTAINER=1).
    host: str = "127.0.0.1"
    in_container: bool = False
    port: int = 8000
    allowed_hosts: list[str] = ["127.0.0.1", "localhost"]
    web_origins: list[str] = ["http://127.0.0.1:3000", "http://localhost:3000"]

    database_url: str = "postgresql+psycopg://reconix:reconix@127.0.0.1:5432/reconix"

    # Kali MCP container, reached over the internal tools network (deploy/docker-compose.yml).
    # RECONIX_MCP_URL is the old name, still read until v1.0.0, so an old .env does not
    # quietly fall back to the default address and send the auth token there.
    kali_mcp_url: str = Field(
        "http://reconix-kali-container:8000/mcp",
        validation_alias=AliasChoices("RECONIX_KALI_MCP_URL", "RECONIX_MCP_URL"),
    )
    # RECONIX_MCP_ACCESS_KEY is the old name, still read until v1.0.0.
    mcp_auth_token: SecretStr = Field(
        SecretStr(""),
        validation_alias=AliasChoices("RECONIX_MCP_AUTH_TOKEN", "RECONIX_MCP_ACCESS_KEY"),
    )
    job_token_secret: SecretStr = SecretStr("")
    job_token_ttl_seconds: int = 300

    # Encrypts the AI provider API keys saved in the database (a Fernet key).
    # RECONIX_FERNET_KEY is the old name, still read until v1.0.0.
    provider_encryption_key: SecretStr = Field(
        SecretStr(""),
        validation_alias=AliasChoices("RECONIX_PROVIDER_ENCRYPTION_KEY", "RECONIX_FERNET_KEY"),
    )

    # Audit log (JSON lines), written by the harness
    audit_log_path: str = "data/audit/audit.jsonl"

    # Report files (PDF, DOCX, JSON), one folder per assessment and version
    reports_dir: str = "data/reports"

    # Source code from the VS Code extension, one folder per session. The Kali container
    # mounts this folder read-only at /workspace/code (deploy/docker-compose.yml).
    code_dir: str = "data/code"
    max_upload_mb: int = 100  # per upload, counted both packed and unpacked
    # Folders searched (4 levels deep) for a clone of a GitHub repo before git clones it,
    # comma-separated in the environment.
    local_repo_roots: Annotated[list[str], NoDecode] = []

    # The real values behind masked evidence, encrypted with
    # RECONIX_PROVIDER_ENCRYPTION_KEY, for a `disclosure` approval. Only this user can open
    # the folder.
    vault_dir: str = "data/vault"

    # Approvals
    approval_ttl_minutes: int = 30

    # GET /stream sends a ping this often, and checks the session is still open
    stream_heartbeat_seconds: float = 15

    # Too many requests: per session token, per minute (429 after that). Signing in
    # (POST /sessions, POST /sessions/web-sign-in) has its own, smaller limit.
    rate_limit_per_minute: int = 600
    sign_in_limit_per_minute: int = 20

    @field_validator("local_repo_roots", mode="before")
    @classmethod
    def split_paths(cls, value: object) -> object:
        if isinstance(value, str):
            return [path.strip() for path in value.split(",") if path.strip()]
        return value

    @model_validator(mode="after")
    def host_must_be_loopback(self) -> Self:
        if self.in_container and self.host == "0.0.0.0":  # noqa: S104  published on 127.0.0.1
            return self
        if self.host != "localhost" and not ipaddress.ip_address(self.host).is_loopback:
            raise ValueError("RECONIX_HOST must be a loopback address")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
