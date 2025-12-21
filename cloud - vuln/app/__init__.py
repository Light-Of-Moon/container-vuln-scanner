"""
Container Vulnerability Scanner - Application Package
=====================================================
This package provides the database models, schemas, services, and API
for the vulnerability scanning platform.
"""

from app.database import (
    Base,
    get_db,
    get_db_session,
    get_engine,
    init_db,
    close_db,
    health_check,
    DatabaseConfig,
)

from app.models import (
    VulnerabilityScan,
    VulnerabilityDetail,
    ScanAuditLog,
    ScanStatus,
    SeverityLevel,
    ComplianceStatus,
)

from app.schemas import (
    ScanRequest,
    ScanBatchRequest,
    ScanSummaryResponse,
    ScanDetailResponse,
    ScanCreatedResponse,
    ScanListResponse,
    VulnerabilityCountsSchema,
    RiskAssessmentSchema,
    ScanTimingSchema,
    VulnerabilityDetailSchema,
    ImageTrendResponse,
    ErrorResponse,
    HealthCheckResponse,
)

from app.exceptions import (
    VulnScannerException,
    ScanNotFoundException,
    ScanAlreadyExistsException,
    ScanFailedException,
    ScanTimeoutException,
    InvalidImageException,
    ImageNotFoundException,
    DatabaseConnectionException,
    RateLimitExceededException,
)

from app.services import ScanService, ScanResult, DashboardStats

from app.worker import (
    ScanWorker,
    WorkerConfig,
    process_scan_job,
    calculate_risk_metrics,
    RiskMetrics,
)

__all__ = [
    # Database
    "Base",
    "get_db",
    "get_db_session",
    "get_engine",
    "init_db",
    "close_db",
    "health_check",
    "DatabaseConfig",
    # Models
    "VulnerabilityScan",
    "VulnerabilityDetail",
    "ScanAuditLog",
    "ScanStatus",
    "SeverityLevel",
    "ComplianceStatus",
    # Schemas
    "ScanRequest",
    "ScanBatchRequest",
    "ScanSummaryResponse",
    "ScanDetailResponse",
    "ScanCreatedResponse",
    "ScanListResponse",
    "VulnerabilityCountsSchema",
    "RiskAssessmentSchema",
    "ScanTimingSchema",
    "VulnerabilityDetailSchema",
    "ImageTrendResponse",
    "ErrorResponse",
    "HealthCheckResponse",
    # Exceptions
    "VulnScannerException",
    "ScanNotFoundException",
    "ScanAlreadyExistsException",
    "ScanFailedException",
    "ScanTimeoutException",
    "InvalidImageException",
    "ImageNotFoundException",
    "DatabaseConnectionException",
    "RateLimitExceededException",
    # Services
    "ScanService",
    "ScanResult",
    "DashboardStats",
    # Worker
    "ScanWorker",
    "WorkerConfig",
    "process_scan_job",
    "calculate_risk_metrics",
    "RiskMetrics",
]

__version__ = "1.0.0"
