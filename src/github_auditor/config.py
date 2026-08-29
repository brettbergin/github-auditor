"""Application settings, loaded from the environment (and optional .env file)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GITHUB_AUDITOR_",
        env_file=".env",
        extra="ignore",
    )

    github_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GITHUB_TOKEN", "GITHUB_AUDITOR_TOKEN"),
    )
    org: str | None = None
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".github-auditor")
    db_path: Path | None = None
    clone_dir: Path | None = None
    cache_ttl_hours: float = 24.0
    max_workers: int = 8
    clone_depth: int = 1
    stale_years: float = 2.0
    # Action owners considered first-party/trusted for pinning rules, besides the audited org.
    trusted_action_owners: list[str] = ["actions", "github"]
    log_level: str = "WARNING"

    @property
    def effective_db_path(self) -> Path:
        return self.db_path if self.db_path is not None else self.data_dir / "cache.db"

    @property
    def effective_clone_dir(self) -> Path:
        return self.clone_dir if self.clone_dir is not None else self.data_dir / "clones"

    def token_value(self) -> str | None:
        return self.github_token.get_secret_value() if self.github_token else None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
