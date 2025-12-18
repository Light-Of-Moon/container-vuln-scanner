"""
Custom Exceptions - Domain-specific Error Handling
==================================================
Provides clear, type-safe exceptions for business logic errors.
All exceptions include error codes for API response mapping.
"""

from typing import Any


class VulnScannerException(Exception):
    """
    Base exception for all vulnerability scanner errors.
    
    Attributes:
        message: Human-readable error description
        error_code: Machine-readable error code for API responses
        details: Additional context (e.g., scan_id, image_name)
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "INTERNAL_ERROR",
        details: dict[str, Any] | None = None,
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert exception to API-friendly dictionary."""
        return {
            "code": self.error_code,
            "message": self.message,
            "details": self.details,
        }


# =============================================================================
# SCAN EXCEPTIONS
# =============================================================================

class ScanNotFoundException(VulnScannerException):
    """Raised when a scan ID does not exist in the database."""
    
    def __init__(self, scan_id: str, message: str | None = None):
        super().__init__(
            message=message or f"Scan with ID '{scan_id}' not found",
            error_code="SCAN_NOT_FOUND",
            details={"scan_id": scan_id},
        )
        self.scan_id = scan_id


class ScanAlreadyExistsException(VulnScannerException):
    """Raised when attempting to create a duplicate scan."""
    
    def __init__(self, image_name: str, existing_scan_id: str):
        super().__init__(
            message=f"Scan for '{image_name}' already in progress",
            error_code="SCAN_ALREADY_EXISTS",
            details={
                "image_name": image_name,
                "existing_scan_id": existing_scan_id,
            },
        )
        self.existing_scan_id = existing_scan_id


class ScanFailedException(VulnScannerException):
    """Raised when a scan operation fails."""
    
    def __init__(
        self,
        scan_id: str,
        reason: str,
        error_code: str = "SCAN_FAILED",
    ):
        super().__init__(
            message=f"Scan '{scan_id}' failed: {reason}",
            error_code=error_code,
            details={"scan_id": scan_id, "reason": reason},
        )
        self.scan_id = scan_id
        self.reason = reason


class ScanTimeoutException(ScanFailedException):
    """Raised when a scan exceeds the maximum allowed time."""
    
    def __init__(self, scan_id: str, timeout_seconds: int):
        super().__init__(
            scan_id=scan_id,
            reason=f"Scan exceeded timeout of {timeout_seconds} seconds",
            error_code="SCAN_TIMEOUT",
        )
        self.timeout_seconds = timeout_seconds


# =============================================================================
# IMAGE EXCEPTIONS
# =============================================================================

class InvalidImageException(VulnScannerException):
    """Raised when an image reference is malformed or invalid."""
    
    def __init__(self, image_name: str, reason: str):
        super().__init__(
            message=f"Invalid image '{image_name}': {reason}",
            error_code="INVALID_IMAGE",
            details={"image_name": image_name, "reason": reason},
        )
        self.image_name = image_name


class ImageNotFoundException(VulnScannerException):
    """Raised when an image cannot be found in the registry."""
    
    def __init__(self, image_name: str, registry: str = "docker.io"):
        super().__init__(
            message=f"Image '{image_name}' not found in registry '{registry}'",
            error_code="IMAGE_NOT_FOUND",
            details={"image_name": image_name, "registry": registry},
        )
        self.image_name = image_name
        self.registry = registry


class ImagePullException(VulnScannerException):
    """Raised when an image cannot be pulled from the registry."""
    
    def __init__(self, image_name: str, reason: str):
        super().__init__(
            message=f"Failed to pull image '{image_name}': {reason}",
            error_code="IMAGE_PULL_FAILED",
            details={"image_name": image_name, "reason": reason},
        )
        self.image_name = image_name


# =============================================================================
# DATABASE EXCEPTIONS
# =============================================================================

class DatabaseConnectionException(VulnScannerException):
    """Raised when database connection fails."""
    
    def __init__(self, message: str = "Database connection failed"):
        super().__init__(
            message=message,
            error_code="DATABASE_ERROR",
        )


class DatabaseTransactionException(VulnScannerException):
    """Raised when a database transaction fails."""
    
    def __init__(self, operation: str, reason: str):
        super().__init__(
            message=f"Database transaction failed during {operation}: {reason}",
            error_code="DATABASE_TRANSACTION_ERROR",
            details={"operation": operation, "reason": reason},
        )


# =============================================================================
# RATE LIMITING EXCEPTIONS
# =============================================================================

class RateLimitExceededException(VulnScannerException):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        limit: int,
        window_seconds: int,
        retry_after: int | None = None,
    ):
        super().__init__(
            message=f"Rate limit exceeded: {limit} requests per {window_seconds} seconds",
            error_code="RATE_LIMIT_EXCEEDED",
            details={
                "limit": limit,
                "window_seconds": window_seconds,
                "retry_after": retry_after,
            },
        )
        self.retry_after = retry_after


class RegistryRateLimitException(VulnScannerException):
    """Raised when container registry rate limit is hit (e.g., Docker Hub)."""
    
    def __init__(self, registry: str, retry_after: int | None = None):
        super().__init__(
            message=f"Registry '{registry}' rate limit exceeded",
            error_code="REGISTRY_RATE_LIMIT",
            details={"registry": registry, "retry_after": retry_after},
        )
        self.registry = registry
        self.retry_after = retry_after


# =============================================================================
# WORKER EXCEPTIONS
# =============================================================================

class WorkerException(VulnScannerException):
    """Base exception for worker-related errors."""
    
    def __init__(self, message: str, worker_id: str | None = None):
        super().__init__(
            message=message,
            error_code="WORKER_ERROR",
            details={"worker_id": worker_id} if worker_id else {},
        )
        self.worker_id = worker_id


class WorkerBusyException(WorkerException):
    """Raised when all workers are busy."""
    
    def __init__(self):
        super().__init__(
            message="All workers are currently busy, please retry later",
        )
        self.error_code = "WORKERS_BUSY"


class TrivyExecutionException(VulnScannerException):
    """Raised when Trivy execution fails."""
    
    def __init__(self, reason: str, exit_code: int | None = None):
        super().__init__(
            message=f"Trivy execution failed: {reason}",
            error_code="TRIVY_ERROR",
            details={"reason": reason, "exit_code": exit_code},
        )
        self.exit_code = exit_code
