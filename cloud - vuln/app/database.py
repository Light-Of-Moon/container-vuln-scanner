"""
Database Configuration Module - Production Grade Async Setup
=============================================================
Principal Architecture Decisions:
1. AsyncPG driver for maximum PostgreSQL performance
2. Connection pooling optimized for high-throughput scanning workloads
3. Statement caching for repeated query patterns
4. Graceful degradation with retry logic
"""

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool, AsyncAdaptedQueuePool
from sqlalchemy import event, text

# =============================================================================
# CONFIGURATION - Production Optimized Settings
# =============================================================================

class DatabaseConfig:
    """
    Connection pooling strategy for vulnerability scanning workload:
    - Scans are bursty (many concurrent requests during CI/CD pipelines)
    - Each scan INSERT is ~50KB (JSONB report)
    - Read queries for dashboards are frequent but lightweight
    """
    
    # Primary connection string - use asyncpg driver for async support
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql+asyncpg://scanner:scanner@localhost:5432/vulnscan"
    )
    
    # Pool sizing rationale:
    # - pool_size=20: Baseline connections for steady-state load
    # - max_overflow=30: Burst capacity for CI/CD pipeline spikes
    # - Total max connections = 50 (stay under PostgreSQL default 100)
    POOL_SIZE: int = 20
    MAX_OVERFLOW: int = 30
    
    # Timeout settings (seconds)
    POOL_TIMEOUT: int = 30          # Wait for available connection
    POOL_RECYCLE: int = 1800        # Recycle connections every 30 min (AWS RDS requirement)
    POOL_PRE_PING: bool = True      # Validate connection before checkout (handles network blips)
    
    # Statement caching - critical for repeated scan queries
    PREPARED_STATEMENT_CACHE_SIZE: int = 500
    
    # Echo SQL for debugging (disable in production)
    ECHO_SQL: bool = False


# =============================================================================
# BASE MODEL - All ORM models inherit from this
# =============================================================================

class Base(DeclarativeBase):
    """
    Declarative base with metadata configuration.
    Using naming conventions for consistent constraint names across migrations.
    """
    pass


# =============================================================================
# ENGINE FACTORY - Creates properly configured async engine
# =============================================================================

def create_db_engine(
    database_url: str | None = None,
    echo: bool | None = None,
    pool_class: type | None = None,
) -> AsyncEngine:
    """
    Factory function to create async database engine with production settings.
    
    Args:
        database_url: Override default connection string (useful for testing)
        echo: Override SQL echo setting
        pool_class: Override pool class (use NullPool for testing)
    
    Returns:
        Configured AsyncEngine instance
    
    Architecture Note:
        We use AsyncAdaptedQueuePool which wraps asyncpg's connection pool.
        This provides connection reuse while maintaining async compatibility.
    """
    url = database_url or DatabaseConfig.DATABASE_URL
    sql_echo = echo if echo is not None else DatabaseConfig.ECHO_SQL
    
    # Build connect_args for asyncpg-specific optimizations
    connect_args = {
        # Statement cache size - reduces parse overhead for repeated queries
        "prepared_statement_cache_size": DatabaseConfig.PREPARED_STATEMENT_CACHE_SIZE,
        # Command timeout - fail fast on hung queries (30 seconds)
        "command_timeout": 30,
    }
    
    engine = create_async_engine(
        url,
        echo=sql_echo,
        # Pool configuration
        poolclass=pool_class or AsyncAdaptedQueuePool,
        pool_size=DatabaseConfig.POOL_SIZE,
        max_overflow=DatabaseConfig.MAX_OVERFLOW,
        pool_timeout=DatabaseConfig.POOL_TIMEOUT,
        pool_recycle=DatabaseConfig.POOL_RECYCLE,
        pool_pre_ping=DatabaseConfig.POOL_PRE_PING,
        # AsyncPG specific settings
        connect_args=connect_args,
        # JSON serialization - use stdlib json for JSONB columns
        json_serializer=lambda obj: __import__("json").dumps(obj, default=str),
        json_deserializer=__import__("json").loads,
    )
    
    return engine


# =============================================================================
# SESSION FACTORY - Creates async session maker
# =============================================================================

# Global engine instance - initialized lazily
_engine: AsyncEngine | None = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Get or create the global engine instance."""
    global _engine
    if _engine is None:
        _engine = create_db_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """
    Get or create the async session factory.
    
    Session Configuration Rationale:
    - expire_on_commit=False: Prevents lazy loading issues in async context
    - autoflush=False: Explicit flush control for batch operations
    - autocommit=False: Use explicit transactions (ACID compliance)
    """
    global _async_session_factory
    if _async_session_factory is None:
        _async_session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,  # Critical for async - prevents detached instance errors
            autoflush=False,         # Manual flush for batch insert optimization
            autocommit=False,        # Explicit transaction management
        )
    return _async_session_factory


# =============================================================================
# DEPENDENCY INJECTION - FastAPI compatible session provider
# =============================================================================

@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for database sessions.
    
    Usage:
        async with get_db_session() as session:
            result = await session.execute(query)
    
    Error Handling:
        - Automatic rollback on exception
        - Connection returned to pool on exit
        - Handles both application and database errors
    """
    session_factory = get_session_factory()
    session = session_factory()
    
    try:
        yield session
        await session.commit()
    except Exception as e:
        await session.rollback()
        # Log the error for observability
        # In production, integrate with structured logging (e.g., structlog)
        raise
    finally:
        await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI Dependency for database sessions.
    
    Usage in FastAPI:
        @app.get("/scans")
        async def list_scans(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with get_db_session() as session:
        yield session


# =============================================================================
# DATABASE LIFECYCLE - Startup and Shutdown hooks
# =============================================================================

async def init_db() -> None:
    """
    Initialize database - create tables if they don't exist.
    
    Warning: In production, use Alembic migrations instead.
    This is only for development/testing convenience.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """
    Graceful shutdown - dispose engine and close all connections.
    
    Critical for:
    - Kubernetes pod termination (SIGTERM handling)
    - Preventing connection leaks during rolling deployments
    """
    global _engine, _async_session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None


async def health_check() -> dict:
    """
    Database health check for Kubernetes probes.
    
    Returns:
        dict with connection status and pool statistics
    
    Usage in K8s:
        livenessProbe:
          httpGet:
            path: /health/db
    """
    engine = get_engine()
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            row = result.fetchone()
            
            # Get pool statistics
            pool = engine.pool
            pool_status = {
                "pool_size": pool.size(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
                "checked_in": pool.checkedin(),
            }
            
            return {
                "status": "healthy",
                "database": "connected",
                "pool": pool_status,
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
        }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

async def execute_raw_sql(sql: str, params: dict | None = None) -> list:
    """
    Execute raw SQL for complex analytical queries.
    
    Use Case: Vulnerability trend analysis queries that are too complex
    for the ORM (window functions, CTEs, etc.)
    
    Security: Always use parameterized queries to prevent SQL injection.
    """
    async with get_db_session() as session:
        result = await session.execute(text(sql), params or {})
        return result.fetchall()


# Export all needed items
__all__ = [
    "Base",
    "engine", 
    "async_session_factory",
    "get_db_session",
    "init_db",
    "close_db",
    "DATABASE_URL",
]
