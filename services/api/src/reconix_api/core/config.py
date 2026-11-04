"""Settings, read from the environment or .env (prefix RECONIX_)."""

import ipaddress
from functools import lru_cache
from typing import Annotated

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RECONIX_", env_file=".env", extra="ignore")

    # The API only ever listens on this computer.
    host: str = "127.0.0.1"
    port: int = 8000
    allowed_hosts: list[str] = ["127.0.0.1", "localhost"]
    web_origins: list[str] = ["http://127.0.0.1:3000", "http://localhost:3000"]

    database_url: str = "postgresql+psycopg://reconix:reconix@127.0.0.1:5432/reconix"

    # Kali MCP container. RECONIX_MCP_URL is the old name, still read until v1.0.0, so an
    # old .env does not quietly fall back to the default port and send the access key there.
    kali_mcp_url: str = Field(
        "http://127.0.0.1:8765/mcp",
        validation_alias=AliasChoices("RECONIX_KALI_MCP_URL", "RECONIX_MCP_URL"),
    )
    mcp_access_key: SecretStr = SecretStr("")
    job_token_secret: SecretStr = SecretStr("")
    job_token_ttl_seconds: int = 300

    # Encrypts AI provider API keys
    fernet_key: SecretStr = SecretStr("")

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

    # Approvals
    approval_ttl_minutes: int = 30

    # GET /stream sends a ping this often, and checks the session is still open
    stream_heartbeat_seconds: float = 15

    @field_validator("local_repo_roots", mode="before")
    @classmethod
    def split_paths(cls, value: object) -> object:
        if isinstance(value, str):
            return [path.strip() for path in value.split(",") if path.strip()]
        return value

    @field_validator("host")
    @classmethod
    def host_must_be_loopback(cls, value: str) -> str:
        if value != "localhost" and not ipaddress.ip_address(value).is_loopback:
            raise ValueError("RECONIX_HOST must be a loopback address")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
