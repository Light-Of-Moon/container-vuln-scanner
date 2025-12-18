"""
Application Configuration - Environment-based Settings
======================================================
Uses Pydantic Settings for type-safe configuration management.
Supports .env files and environment variable overrides.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings with validation and defaults.
    
    Configuration Hierarchy (highest to lowest priority):
    1. Environment variables
    2. .env file
    3. Default values
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # =========================================================================
    # APPLICATION
    # =========================================================================
    
    app_name: str = Field(
        default="Container Vulnerability Scanner",
        description="Application name for logging and metrics",
    )
    
    app_version: str = Field(
        default="1.0.0",
        description="Application version",
    )
    
    environment: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Deployment environment",
    )
    
    debug: bool = Field(
        default=False,
        description="Enable debug mode (verbose logging, SQL echo)",
    )
    
    # =========================================================================
    # DATABASE
    # =========================================================================
    
    database_url: str = Field(
        default="postgresql+asyncpg://scanner:scanner@localhost:5432/vulnscan",
        description="PostgreSQL connection string (asyncpg driver)",
    )
    
    db_pool_size: int = Field(
        default=20,
        ge=5,
        le=100,
        description="Database connection pool size",
    )
    
    db_max_overflow: int = Field(
        default=30,
        ge=0,
        le=100,
        description="Maximum overflow connections beyond pool_size",
    )
    
    db_pool_timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Seconds to wait for available connection",
    )
    
    db_pool_recycle: int = Field(
        default=1800,
        ge=300,
        description="Recycle connections after N seconds (AWS RDS requires 1800)",
    )
    
    db_echo_sql: bool = Field(
        default=False,
        description="Echo SQL statements (debug only)",
    )
    
    # =========================================================================
    # SCAN CONFIGURATION
    # =========================================================================
    
    scan_cache_ttl_minutes: int = Field(
        default=60,
        ge=5,
        le=1440,
        description="Cache TTL for idempotent scan results (minutes)",
    )
    
    scan_timeout_seconds: int = Field(
        default=600,
        ge=60,
        le=3600,
        description="Maximum time for a single scan operation",
    )
    
    scan_max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum retry attempts for failed scans",
    )
    
    # =========================================================================
    # TRIVY CONFIGURATION
    # =========================================================================
    
    trivy_binary_path: str = Field(
        default="/usr/local/bin/trivy",
        description="Path to Trivy binary",
    )
    
    trivy_cache_dir: str = Field(
        default="/tmp/trivy-cache",
        description="Trivy vulnerability database cache directory",
    )
    
    trivy_timeout_seconds: int = Field(
        default=300,
        ge=60,
        le=1800,
        description="Timeout for Trivy subprocess",
    )
    
    # =========================================================================
    # WORKER CONFIGURATION
    # =========================================================================
    
    worker_concurrency: int = Field(
        default=4,
        ge=1,
        le=16,
        description="Number of concurrent scan workers",
    )
    
    worker_poll_interval_seconds: int = Field(
        default=5,
        ge=1,
        le=60,
        description="Interval between polling for new jobs",
    )
    
    # =========================================================================
    # API CONFIGURATION
    # =========================================================================
    
    api_host: str = Field(
        default="0.0.0.0",
        description="API server bind host",
    )
    
    api_port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="API server bind port",
    )
    
    api_workers: int = Field(
        default=4,
        ge=1,
        le=32,
        description="Number of Uvicorn workers",
    )
    
    cors_origins: list[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins",
    )
    
    # =========================================================================
    # RISK SCORING WEIGHTS
    # =========================================================================
    
    risk_weight_critical: int = Field(default=100, ge=1)
    risk_weight_high: int = Field(default=50, ge=1)
    risk_weight_medium: int = Field(default=10, ge=1)
    risk_weight_low: int = Field(default=1, ge=1)
    
    # =========================================================================
    # OBSERVABILITY
    # =========================================================================
    
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )
    
    log_format: Literal["json", "text"] = Field(
        default="json",
        description="Log output format",
    )
    
    metrics_enabled: bool = Field(
        default=True,
        description="Enable Prometheus metrics endpoint",
    )
    
    tracing_enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry tracing",
    )
    
    # =========================================================================
    # VALIDATORS
    # =========================================================================
    
    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Ensure database URL uses asyncpg driver."""
        if "postgresql://" in v and "asyncpg" not in v:
            # Auto-convert to asyncpg driver
            return v.replace("postgresql://", "postgresql+asyncpg://")
        return v
    
    # =========================================================================
    # COMPUTED PROPERTIES
    # =========================================================================
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Uses lru_cache to ensure settings are only loaded once.
    Call get_settings.cache_clear() to reload.
    """
    return Settings()


# Convenience export
settings = get_settings()
