"""Application configuration using Pydantic Settings."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server settings
    ENVIRONMENT: str = "development"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    # Database
    DATABASE_URL: str = "postgresql+psycopg://postgres:postgres@localhost:5432/phishing_db"

    # Security & CORS: specific origins only, no wildcard
    ALLOWED_ORIGINS: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    )

    # External Provider Keys (Server-side only)
    GEMINI_API_KEY: str | None = None
    SAFE_BROWSING_API_KEY: str | None = None

    # Retention
    SCAN_RETENTION_DAYS: int = Field(default=30, gt=0)
    RETENTION_CHECK_INTERVAL_SECONDS: int = Field(default=86400, gt=0)
    RETENTION_INITIAL_DELAY_SECONDS: int = Field(default=5, ge=0)


settings = Settings()
