"""
Container Vulnerability Scanner - FastAPI Application
"""

import os
import uuid
import logging
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc

from app.database import get_engine, get_session_factory, Base, get_db_session, init_db, close_db
from app.models import VulnerabilityScan, ScanStatus, ComplianceStatus

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app.main")


# =============================================================================
# Pydantic Models
# =============================================================================

class ScanRequest(BaseModel):
    """Request model for initiating a scan"""
    image_name: str = Field(..., min_length=1, max_length=255)
    image_tag: str = Field(default="latest", max_length=128)
    registry: str = Field(default="docker.io", max_length=255)
    force_rescan: bool = Field(default=False)


class ScanResponse(BaseModel):
    """Response model for scan results"""
    id: str
    image_name: str
    image_tag: str
    registry: str
    status: str
    risk_score: int = 0
    is_compliant: bool = False
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_vulnerabilities: int = 0
    fixable_count: int = 0
    scan_duration: Optional[float] = None
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    raw_report: Optional[dict] = None

    class Config:
        from_attributes = True


class PaginatedScans(BaseModel):
    """Paginated list of scans"""
    items: List[ScanResponse]
    total: int
    page: int
    page_size: int
    pages: int


class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_scans: int = 0
    completed_scans: int = 0
    failed_scans: int = 0
    active_scans: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    fixable_percentage: float = 0.0
    avg_risk_score: float = 0.0


# =============================================================================
# Application Lifecycle
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown"""
    logger.info("Starting Container Vulnerability Scanner API...")
    
    # Initialize database tables
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
    
    yield
    
    # Cleanup
    logger.info("Shutting down API...")
    await close_db()


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Container Vulnerability Scanner",
    description="Scan Docker images for security vulnerabilities using Trivy",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler to ensure all errors return JSON
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch all unhandled exceptions and return a JSON response"""
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "message": str(exc) if os.getenv("DEBUG", "false").lower() == "true" else "An unexpected error occurred",
        }
    )


# Request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    start_time = datetime.utcnow()
    
    response = await call_next(request)
    
    duration = (datetime.utcnow() - start_time).total_seconds()
    logger.info(
        f"{request.method} {request.url.path} "
        f"status={response.status_code} "
        f"duration={duration:.3f}s "
        f"request_id={request_id}"
    )
    
    response.headers["X-Request-ID"] = request_id
    return response


# =============================================================================
# Health Check
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# =============================================================================
# Scan Endpoints
# =============================================================================

@app.post("/api/v1/scan", status_code=202)
async def create_scan(
    request: ScanRequest,
):
    """
    Submit a new vulnerability scan request.
    
    The scan will be picked up by the worker service for processing.
    """
    from app.services import create_scan_request
    
    async with get_db_session() as session:
        scan = await create_scan_request(
            session=session,
            image_name=request.image_name,
            image_tag=request.image_tag,
            registry=request.registry,
            force_rescan=request.force_rescan,
        )
        
        # Scan is created with PENDING status
        # The worker service polls for pending scans and processes them
        # This decouples the API from scan execution
        
        return {
            "id": str(scan.id),
            "image_name": scan.image_name,
            "image_tag": scan.image_tag,
            "status": scan.status.value,
            "message": "Scan queued successfully",
        }


@app.get("/api/v1/scans", response_model=PaginatedScans)
async def list_scans(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = None,
    image_name: Optional[str] = None,
):
    """
    List all vulnerability scans with pagination.
    """
    async with get_db_session() as session:
        # Build query
        query = select(VulnerabilityScan)
        count_query = select(func.count(VulnerabilityScan.id))
        
        # Apply filters
        if status:
            query = query.where(VulnerabilityScan.status == status)
            count_query = count_query.where(VulnerabilityScan.status == status)
        if image_name:
            query = query.where(VulnerabilityScan.image_name.ilike(f"%{image_name}%"))
            count_query = count_query.where(VulnerabilityScan.image_name.ilike(f"%{image_name}%"))
        
        # Get total count
        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0
        
        # Apply pagination
        query = query.order_by(desc(VulnerabilityScan.created_at))
        query = query.offset((page - 1) * page_size).limit(page_size)
        
        result = await session.execute(query)
        scans = result.scalars().all()
        
        return PaginatedScans(
            items=[
                ScanResponse(
                    id=str(s.id),
                    image_name=s.image_name,
                    image_tag=s.image_tag,
                    registry=s.registry,
                    status=s.status.value,
                    risk_score=s.risk_score,
                    is_compliant=s.is_compliant,
                    critical_count=s.critical_count,
                    high_count=s.high_count,
                    medium_count=s.medium_count,
                    low_count=s.low_count,
                    total_vulnerabilities=s.total_vulnerabilities,
                    fixable_count=s.fixable_count,
                    scan_duration=s.scan_duration,
                    error_message=s.error_message,
                    created_at=s.created_at,
                    completed_at=s.completed_at,
                )
                for s in scans
            ],
            total=total,
            page=page,
            page_size=page_size,
            pages=(total + page_size - 1) // page_size,
        )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    """
    Get detailed scan results by ID.
    """
    async with get_db_session() as session:
        result = await session.execute(
            select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return ScanResponse(
            id=str(scan.id),
            image_name=scan.image_name,
            image_tag=scan.image_tag,
            registry=scan.registry,
            status=scan.status.value,
            risk_score=scan.risk_score,
            is_compliant=scan.is_compliant,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            total_vulnerabilities=scan.total_vulnerabilities,
            fixable_count=scan.fixable_count,
            scan_duration=scan.scan_duration,
            error_message=scan.error_message,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            raw_report=scan.raw_report,
        )


@app.delete("/api/v1/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Delete a scan and all its related data from the database.
    """
    async with get_db_session() as session:
        # First check if scan exists
        result = await session.execute(
            select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Delete related audit logs first (if any)
        try:
            from app.models import ScanAuditLog
            await session.execute(
                select(ScanAuditLog).where(ScanAuditLog.scan_id == scan_id)
            )
            # Delete audit logs
            from sqlalchemy import delete
            await session.execute(
                delete(ScanAuditLog).where(ScanAuditLog.scan_id == scan_id)
            )
        except Exception as e:
            logger.warning(f"Could not delete audit logs for scan {scan_id}: {e}")
        
        # Delete related vulnerability details (if any)
        try:
            from app.models import VulnerabilityDetail
            from sqlalchemy import delete
            await session.execute(
                delete(VulnerabilityDetail).where(VulnerabilityDetail.scan_id == scan_id)
            )
        except Exception as e:
            logger.warning(f"Could not delete vulnerability details for scan {scan_id}: {e}")
        
        # Delete the scan
        await session.delete(scan)
        await session.commit()
        
        logger.info(f"Deleted scan {scan_id} and related data")
        
        return {"message": "Scan deleted successfully", "id": scan_id}


@app.get("/api/v1/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """
    Get aggregated dashboard statistics.
    """
    async with get_db_session() as session:
        # Get counts by status
        result = await session.execute(
            select(
                func.count(VulnerabilityScan.id).label("total"),
                func.count(VulnerabilityScan.id).filter(
                    VulnerabilityScan.status == ScanStatus.completed
                ).label("completed"),
                func.count(VulnerabilityScan.id).filter(
                    VulnerabilityScan.status == ScanStatus.failed
                ).label("failed"),
                func.count(VulnerabilityScan.id).filter(
                    VulnerabilityScan.status.in_([
                        ScanStatus.pending, ScanStatus.pulling,
                        ScanStatus.scanning, ScanStatus.parsing
                    ])
                ).label("active"),
                func.sum(VulnerabilityScan.critical_count).label("critical"),
                func.sum(VulnerabilityScan.high_count).label("high"),
                func.sum(VulnerabilityScan.medium_count).label("medium"),
                func.sum(VulnerabilityScan.low_count).label("low"),
                func.count(VulnerabilityScan.id).filter(
                    VulnerabilityScan.is_compliant == True
                ).label("compliant"),
                func.avg(VulnerabilityScan.risk_score).label("avg_risk"),
                func.sum(VulnerabilityScan.fixable_count).label("fixable"),
                func.sum(VulnerabilityScan.total_vulnerabilities).label("total_vulns"),
            )
        )
        
        row = result.one()
        
        total_vulns = row.total_vulns or 0
        fixable = row.fixable or 0
        fixable_pct = (fixable / total_vulns * 100) if total_vulns > 0 else 0
        
        return DashboardStats(
            total_scans=row.total or 0,
            completed_scans=row.completed or 0,
            failed_scans=row.failed or 0,
            active_scans=row.active or 0,
            critical_count=row.critical or 0,
            high_count=row.high or 0,
            medium_count=row.medium or 0,
            low_count=row.low or 0,
            compliant_count=row.compliant or 0,
            non_compliant_count=(row.completed or 0) - (row.compliant or 0),
            fixable_percentage=round(fixable_pct, 1),
            avg_risk_score=round(row.avg_risk or 0, 1),
        )


# =============================================================================
# Upload Router (imported after app is defined)
# =============================================================================

try:
    from app.routes.upload import router as upload_router
    app.include_router(upload_router, prefix="/api/v1", tags=["upload"])
except ImportError as e:
    logger.warning(f"Upload router not available: {e}")
