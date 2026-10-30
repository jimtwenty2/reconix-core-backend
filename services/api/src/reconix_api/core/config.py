"""Settings, read from the environment or .env (prefix RECONIX_)."""

import ipaddress
from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RECONIX_", env_file=".env", extra="ignore")

    # The API only ever listens on this computer.
    host: str = "127.0.0.1"
    port: int = 8000
    allowed_hosts: list[str] = ["127.0.0.1", "localhost"]
    web_origins: list[str] = ["http://127.0.0.1:3000", "http://localhost:3000"]

    database_url: str = "postgresql+psycopg://reconix:reconix@127.0.0.1:5432/reconix"

    # Kali MCP container
    mcp_url: str = "http://127.0.0.1:8765/mcp"
    mcp_access_key: SecretStr = SecretStr("")
    job_token_secret: SecretStr = SecretStr("")
    job_token_ttl_seconds: int = 300

    # Encrypts AI provider API keys
    fernet_key: SecretStr = SecretStr("")

    # Audit log (JSON lines), written by the harness
    audit_log_path: str = "data/audit/audit.jsonl"

    # Report files (PDF, DOCX, JSON), one folder per assessment and version
    reports_dir: str = "data/reports"

    # Approvals
    approval_ttl_minutes: int = 30

    @field_validator("host")
    @classmethod
    def host_must_be_loopback(cls, value: str) -> str:
        if value != "localhost" and not ipaddress.ip_address(value).is_loopback:
            raise ValueError("RECONIX_HOST must be a loopback address")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
