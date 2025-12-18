"""
FastAPI Application - Container Vulnerability Scanner API
=========================================================
Production-grade API with:
1. Strict idempotency for scan requests
2. Rate limiting per client
3. Graceful error handling
4. Health checks for Kubernetes
5. CORS and security middleware

API Design:
- POST /api/v1/scan - Submit scan with idempotency
- GET /api/v1/scan/{id} - Get full scan report
- GET /api/v1/scan/{id}/status - Lightweight status polling
- GET /api/v1/scans - List scans with pagination
- GET /api/v1/dashboard/stats - Aggregated metrics
"""

import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    BackgroundTasks,
    Query,
    Path,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.database import get_db, init_db, close_db, health_check as db_health_check
from app.services import ScanService
from app.schemas import (
    ScanRequest,
    ScanCreatedResponse,
    ScanDetailResponse,
    ScanSummaryResponse,
    ScanListResponse,
    PaginationMeta,
    ErrorResponse,
    ErrorDetail,
    HealthCheckResponse,
    ScanStatusEnum,
)
from app.exceptions import (
    VulnScannerException,
    ScanNotFoundException,
    DatabaseConnectionException,
    RateLimitExceededException,
)

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# =============================================================================
# APPLICATION STARTUP TIME (for uptime calculation)
# =============================================================================

APP_START_TIME = time.time()

# =============================================================================
# LIFESPAN MANAGER - Startup/Shutdown Events
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Startup:
    - Initialize database connection pool
    - Create tables if needed (dev only)
    
    Shutdown:
    - Close all database connections gracefully
    """
    logger.info("Starting Container Vulnerability Scanner API...")
    
    # Startup
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        # Don't fail startup - let health checks report the issue
    
    yield
    
    # Shutdown
    logger.info("Shutting down API...")
    await close_db()
    logger.info("Database connections closed")


# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

app = FastAPI(
    title=settings.app_name,
    description="""
    ## Container Vulnerability Scanner API
    
    A production-grade vulnerability scanning platform for Docker images.
    
    ### Features:
    - **Idempotent Scanning**: Duplicate requests within 1 hour return cached results
    - **Real-time Status**: Poll scan status with progress percentage
    - **Risk Scoring**: Custom weighted scoring (Critical=100, High=50, etc.)
    - **Compliance Tracking**: Automatic compliance classification
    
    ### Authentication:
    Currently using API key authentication (header: X-API-Key)
    """,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# =============================================================================
# MIDDLEWARE
# =============================================================================

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining"],
)


@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    """
    Add unique request ID for tracing.
    
    The request ID is:
    1. Read from X-Request-ID header if provided
    2. Generated as UUID if not provided
    3. Attached to response headers
    4. Available in request.state for logging
    """
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    
    # Process request
    response = await call_next(request)
    
    # Add request ID to response
    response.headers["X-Request-ID"] = request_id
    
    return response


@app.middleware("http")
async def log_requests_middleware(request: Request, call_next):
    """Log all incoming requests with timing."""
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration = time.time() - start_time
    
    # Log (skip health checks to reduce noise)
    if not request.url.path.startswith("/health"):
        logger.info(
            f"{request.method} {request.url.path} "
            f"status={response.status_code} "
            f"duration={duration:.3f}s "
            f"request_id={getattr(request.state, 'request_id', 'unknown')}"
        )
    
    return response


# =============================================================================
# EXCEPTION HANDLERS
# =============================================================================

@app.exception_handler(VulnScannerException)
async def vuln_scanner_exception_handler(
    request: Request,
    exc: VulnScannerException,
) -> JSONResponse:
    """Handle custom domain exceptions."""
    
    # Map error codes to HTTP status codes
    status_code_map = {
        "SCAN_NOT_FOUND": status.HTTP_404_NOT_FOUND,
        "INVALID_IMAGE": status.HTTP_400_BAD_REQUEST,
        "RATE_LIMIT_EXCEEDED": status.HTTP_429_TOO_MANY_REQUESTS,
        "DATABASE_ERROR": status.HTTP_503_SERVICE_UNAVAILABLE,
        "DATABASE_TRANSACTION_ERROR": status.HTTP_503_SERVICE_UNAVAILABLE,
        "SCAN_ALREADY_EXISTS": status.HTTP_409_CONFLICT,
    }
    
    http_status = status_code_map.get(exc.error_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return JSONResponse(
        status_code=http_status,
        content={
            "status": "error",
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
            },
            "request_id": getattr(request.state, "request_id", None),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Handle Pydantic validation errors."""
    
    # Extract first error for simple message
    errors = exc.errors()
    first_error = errors[0] if errors else {}
    field = ".".join(str(loc) for loc in first_error.get("loc", []))
    message = first_error.get("msg", "Validation error")
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "error",
            "error": {
                "code": "VALIDATION_ERROR",
                "message": f"Invalid input: {message}",
                "field": field,
                "details": {"errors": errors},
            },
            "request_id": getattr(request.state, "request_id", None),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(
    request: Request,
    exc: SQLAlchemyError,
) -> JSONResponse:
    """Handle database errors gracefully."""
    
    logger.error(f"Database error: {exc}")
    
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "error",
            "error": {
                "code": "DATABASE_ERROR",
                "message": "Database temporarily unavailable",
                "details": None,  # Don't expose internal details
            },
            "request_id": getattr(request.state, "request_id", None),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Catch-all handler for unexpected errors."""
    
    logger.exception(f"Unexpected error: {exc}")
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "details": None,
            },
            "request_id": getattr(request.state, "request_id", None),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# =============================================================================
# HEALTH CHECK ENDPOINTS
# =============================================================================

@app.get(
    "/health",
    tags=["Health"],
    response_model=HealthCheckResponse,
    summary="Basic health check",
)
async def health_check() -> HealthCheckResponse:
    """
    Basic health check for load balancers.
    
    Returns 200 if the API is running.
    Does NOT check database (use /health/ready for that).
    """
    return HealthCheckResponse(
        status="healthy",
        version=settings.app_version,
        database="unchecked",
        worker="unchecked",
        uptime_seconds=round(time.time() - APP_START_TIME, 2),
    )


@app.get(
    "/health/ready",
    tags=["Health"],
    response_model=HealthCheckResponse,
    summary="Readiness check (includes database)",
)
async def readiness_check() -> HealthCheckResponse:
    """
    Readiness check for Kubernetes.
    
    Verifies:
    - Database connection is healthy
    - Connection pool has available connections
    
    Use this for readinessProbe in Kubernetes.
    """
    db_status = await db_health_check()
    
    is_ready = db_status.get("status") == "healthy"
    
    return HealthCheckResponse(
        status="healthy" if is_ready else "unhealthy",
        version=settings.app_version,
        database=db_status.get("database", "unknown"),
        worker="unchecked",  # TODO: Add worker health check
        uptime_seconds=round(time.time() - APP_START_TIME, 2),
    )


@app.get(
    "/health/live",
    tags=["Health"],
    status_code=status.HTTP_200_OK,
    summary="Liveness check",
)
async def liveness_check() -> dict:
    """
    Liveness check for Kubernetes.
    
    Returns 200 if the process is alive.
    Use this for livenessProbe in Kubernetes.
    """
    return {"status": "alive"}


# =============================================================================
# SCAN ENDPOINTS
# =============================================================================

async def get_scan_service(db: AsyncSession = Depends(get_db)) -> ScanService:
    """
    Dependency injection for ScanService.
    
    This allows:
    - Easy mocking in tests
    - Consistent service instantiation
    - Proper session lifecycle management
    """
    return ScanService(db)


@app.post(
    "/api/v1/scan",
    tags=["Scans"],
    response_model=ScanCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a vulnerability scan request",
    responses={
        200: {"description": "Cached result returned (cache hit)", "headers": {
            "X-Cache": {"description": "HIT if cached result returned", "schema": {"type": "string"}}
        }},
        202: {"description": "New scan queued"},
        409: {"description": "Scan already in progress"},
        422: {"description": "Validation error"},
        503: {"description": "Database unavailable"},
    },
)
async def submit_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> Response:
    """
    Submit a vulnerability scan request with idempotency.
    
    ## Idempotency Behavior:
    
    - If a **COMPLETED** scan for the same image exists from the last **60 minutes**,
      the cached result is returned immediately (HTTP 200 + `X-Cache: HIT` header).
    - If no cached result exists, a new scan is queued (HTTP 202 + `X-Cache: MISS`).
    - Use `force_rescan: true` to bypass the cache.
    
    ## Request Body:
    
    ```json
    {
        "image_name": "nginx",
        "image_tag": "latest",
        "registry": "docker.io",
        "force_rescan": false
    }
    ```
    
    ## Response Headers:
    
    - `X-Cache: HIT` - Result returned from cache
    - `X-Cache: MISS` - New scan triggered
    - `X-Cache: BYPASS` - Cache bypassed (force_rescan=true)
    
    ## Response Body:
    
    - `cache_hit: true` indicates a cached result was returned
    - `poll_url` provides the endpoint to check scan status
    """
    result = await service.submit_scan_request(
        image_name=request.image_name,
        image_tag=request.image_tag,
        registry=request.registry,
        force_rescan=request.force_rescan,
        background_tasks=background_tasks,
        triggered_by=getattr(http_request.state, "request_id", "api"),
    )
    
    # Determine response status code and cache header
    # 200 for cache hit, 202 for new scan queued
    if result.cache_hit:
        response_status = status.HTTP_200_OK
        cache_header = "HIT"
    elif request.force_rescan:
        response_status = status.HTTP_202_ACCEPTED
        cache_header = "BYPASS"
    else:
        response_status = status.HTTP_202_ACCEPTED
        cache_header = "MISS"
    
    response_data = ScanCreatedResponse(
        id=result.scan.id,
        status=ScanStatusEnum(result.scan.status.value),
        full_image=result.full_image,
        cache_hit=result.cache_hit,
        cached_at=result.scan.created_at if result.cache_hit else None,
        message=(
            "Returning cached scan result"
            if result.cache_hit
            else "Scan queued successfully"
        ),
    )
    
    # Return with appropriate status code and X-Cache header
    return JSONResponse(
        status_code=response_status,
        content=response_data.model_dump(mode="json"),
        headers={"X-Cache": cache_header},
    )


@app.get(
    "/api/v1/scan/{scan_id}",
    tags=["Scans"],
    response_model=ScanDetailResponse,
    summary="Get full scan report",
    responses={
        404: {"description": "Scan not found"},
        503: {"description": "Database unavailable"},
    },
)
async def get_scan(
    scan_id: Annotated[uuid.UUID, Path(description="Scan UUID")],
    service: Annotated[ScanService, Depends(get_scan_service)],
    include_raw: Annotated[bool, Query(description="Include raw Trivy JSON")] = False,
) -> ScanDetailResponse:
    """
    Get full scan details including vulnerability metrics.
    
    ## Parameters:
    
    - `scan_id`: UUID of the scan
    - `include_raw`: Set to `true` to include the full Trivy JSON output
      (warning: can be very large, ~50KB-5MB)
    
    ## Response:
    
    Returns complete scan details with:
    - Vulnerability counts by severity
    - Risk assessment with compliance status
    - Timing metrics
    - Raw Trivy report (if requested)
    """
    scan = await service.get_scan_by_id(scan_id)
    
    # Build response
    response = ScanDetailResponse.model_validate(scan)
    
    # Optionally exclude raw report (default behavior)
    if not include_raw:
        response.raw_report = None
    
    return response


@app.get(
    "/api/v1/scan/{scan_id}/status",
    tags=["Scans"],
    summary="Get scan status (lightweight)",
    responses={
        404: {"description": "Scan not found"},
    },
)
async def get_scan_status(
    scan_id: Annotated[uuid.UUID, Path(description="Scan UUID")],
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> dict:
    """
    Get lightweight scan status for polling.
    
    ## Use Case:
    
    Poll this endpoint every 3-5 seconds while `is_terminal` is `false`.
    
    ## Response:
    
    ```json
    {
        "id": "uuid",
        "status": "scanning",
        "is_terminal": false,
        "progress": 50,
        "error_message": null
    }
    ```
    
    ## Progress Values:
    
    - `pending`: 0%
    - `pulling`: 20%
    - `scanning`: 50%
    - `parsing`: 80%
    - `completed`: 100%
    - `failed`: 100%
    """
    return await service.get_scan_status(scan_id)


@app.get(
    "/api/v1/scans",
    tags=["Scans"],
    response_model=ScanListResponse,
    summary="List all scans with pagination",
)
async def list_scans(
    service: Annotated[ScanService, Depends(get_scan_service)],
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    status_filter: Annotated[ScanStatusEnum | None, Query(alias="status")] = None,
    image: Annotated[str | None, Query(description="Filter by image name")] = None,
    compliant_only: Annotated[bool, Query(description="Only compliant scans")] = False,
) -> ScanListResponse:
    """
    List scans with filtering and pagination.
    
    ## Filters:
    
    - `status`: Filter by scan status (pending, scanning, completed, failed)
    - `image`: Filter by image name (partial match)
    - `compliant_only`: Only return compliant scans
    
    ## Pagination:
    
    - Default page size: 20
    - Maximum page size: 100
    """
    # Convert Pydantic enum to SQLAlchemy enum if provided
    from app.models import ScanStatus as ModelScanStatus
    sa_status = None
    if status_filter:
        sa_status = ModelScanStatus(status_filter.value)
    
    scans, total = await service.list_scans(
        page=page,
        page_size=page_size,
        status=sa_status,
        image_filter=image,
        compliant_only=compliant_only,
    )
    
    # Calculate pagination metadata
    total_pages = (total + page_size - 1) // page_size if total > 0 else 0
    
    return ScanListResponse(
        items=[ScanSummaryResponse.model_validate(s) for s in scans],
        pagination=PaginationMeta(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
        ),
    )


# =============================================================================
# DASHBOARD ENDPOINTS
# =============================================================================

@app.get(
    "/api/v1/dashboard/stats",
    tags=["Dashboard"],
    summary="Get aggregated dashboard statistics",
)
async def get_dashboard_stats(
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> dict:
    """
    Get aggregated metrics for the security dashboard.
    
    ## Response:
    
    ```json
    {
        "total_scans": 1234,
        "completed_scans": 1200,
        "failed_scans": 34,
        "pending_scans": 5,
        "compliant_images": 800,
        "non_compliant_images": 400,
        "compliance_rate": 66.67,
        "average_risk_score": 45.2,
        "top_risky_images": [...],
        "recent_scans": [...]
    }
    ```
    """
    stats = await service.get_dashboard_stats()
    
    return {
        "total_scans": stats.total_scans,
        "completed_scans": stats.completed_scans,
        "failed_scans": stats.failed_scans,
        "pending_scans": stats.pending_scans,
        "compliant_images": stats.compliant_images,
        "non_compliant_images": stats.non_compliant_images,
        "compliance_rate": stats.compliance_rate,
        "average_risk_score": stats.average_risk_score,
        "top_risky_images": stats.top_risky_images,
        "recent_scans": [
            ScanSummaryResponse.model_validate(s).model_dump(mode="json")
            for s in stats.recent_scans[:10]
        ],
    }


@app.get(
    "/api/v1/dashboard/trend/{image_name}",
    tags=["Dashboard"],
    summary="Get vulnerability trend for an image",
)
async def get_image_trend(
    image_name: Annotated[str, Path(description="Image name")],
    service: Annotated[ScanService, Depends(get_scan_service)],
    tag: Annotated[str, Query(description="Image tag")] = "latest",
    days: Annotated[int, Query(ge=1, le=365, description="Days of history")] = 30,
) -> dict:
    """
    Get vulnerability trend for a specific image over time.
    
    ## Use Case:
    
    Track security posture changes for an image across multiple scans.
    
    ## Response:
    
    ```json
    {
        "image": "nginx:latest",
        "trend_direction": "IMPROVING",
        "data_points": [
            {
                "date": "2024-01-01T00:00:00Z",
                "risk_score": 150,
                "total_vulnerabilities": 25,
                "critical_count": 1,
                "high_count": 2
            }
        ]
    }
    ```
    """
    data_points = await service.get_image_trend(image_name, tag, days)
    
    # Calculate trend direction
    trend = "INSUFFICIENT_DATA"
    if len(data_points) >= 2:
        first_score = data_points[0]["risk_score"]
        last_score = data_points[-1]["risk_score"]
        if last_score < first_score:
            trend = "IMPROVING"
        elif last_score > first_score:
            trend = "DEGRADING"
        else:
            trend = "STABLE"
    
    return {
        "image": f"{image_name}:{tag}",
        "trend_direction": trend,
        "data_points": data_points,
    }


# =============================================================================
# ROOT ENDPOINT
# =============================================================================

@app.get("/", tags=["Root"])
async def root() -> dict:
    """API root - basic info and links."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "api": "/api/v1",
    }


# =============================================================================
# DEVELOPMENT SERVER
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.is_development,
        workers=1 if settings.is_development else settings.api_workers,
    )
