"""
app/core/config.py

Application configuration.

Settings are read from environment variables and from a .env file.
All values have documented defaults. No secrets are ever hardcoded here.

Usage:
    from app.core.config import settings
    print(settings.app_env)
"""

from typing import Any
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central application settings.

    Values are loaded from environment variables (case-insensitive).
    A .env file in the project root is also read automatically.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─────────────────────────────────────────────
    # Application identity
    # ─────────────────────────────────────────────
    app_env: str = Field(default="development", description="Runtime environment: development | production | test")
    app_debug: bool = Field(default=False, description="Enable debug mode")
    app_log_level: str = Field(default="INFO", description="Log level: DEBUG | INFO | WARNING | ERROR | CRITICAL")
    app_log_format: str = Field(default="text", description="Log format: text | json")

    # ─────────────────────────────────────────────
    # API server
    # ─────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", description="API server bind host")
    api_port: int = Field(default=8000, description="API server bind port")
    allowed_origins: list[str] = Field(
        default=["*"],
        description="Allowed CORS origins list or '*' for all"
    )

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            if not v or v.strip() == "*":
                return ["*"]
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

    # ─────────────────────────────────────────────
    # Database (MongoDB)
    # ─────────────────────────────────────────────
    mongodb_url: str = Field(
        default="",
        description="MongoDB connection string (e.g. mongodb+srv://user:pass@cluster0.e6m50ew.mongodb.net/)"
    )
    mongodb_db_name: str = Field(
        default="asm_shield_db",
        description="MongoDB database name"
    )
    db_storage_type: str = Field(
        default="in_memory",
        description="Database storage driver: in_memory | mongodb"
    )


    # ─────────────────────────────────────────────
    # Scanner defaults
    # Individual scanners may override these per-scanner.
    # ─────────────────────────────────────────────
    default_scan_timeout_seconds: int = Field(
        default=10,
        description="Default network operation timeout in seconds",
        ge=1,
        le=300,
    )
    default_max_concurrent_scans: int = Field(
        default=5,
        description="Default maximum concurrent scan operations",
        ge=1,
        le=50,
    )

    @property
    def is_development(self) -> bool:
        """Return True when running in development mode."""
        return self.app_env.lower() == "development"

    @property
    def is_production(self) -> bool:
        """Return True when running in production mode."""
        return self.app_env.lower() == "production"

    @property
    def is_test(self) -> bool:
        """Return True when running under the test suite."""
        return self.app_env.lower() == "test"


# Single application-wide settings instance.
# Import this object wherever configuration is needed.
settings = Settings()
