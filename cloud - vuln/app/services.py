"""
Service Layer - Business Logic for Vulnerability Scanning
==========================================================
Implements:
1. Idempotency logic for scan requests
2. Cache management (return cached results within TTL)
3. Background task coordination
4. Scan lifecycle management

Architecture Note:
    Services are stateless and receive dependencies via __init__.
    This allows easy testing via dependency injection.
"""

import logging
from datetime import datetime, timezone
from typing import Sequence
from uuid import UUID

from fastapi import BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.models import VulnerabilityScan, ScanStatus, ComplianceStatus
from app.repositories import ScanRepository, AuditLogRepository
from app.exceptions import (
    ScanNotFoundException,
    ScanAlreadyExistsException,
    DatabaseConnectionException,
    DatabaseTransactionException,
)

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES - Service Layer DTOs
# =============================================================================

class ScanResult:
    """
    Service-layer result object for scan operations.
    
    Encapsulates the scan entity plus metadata about how it was retrieved.
    """
    
    def __init__(
        self,
        scan: VulnerabilityScan,
        cache_hit: bool = False,
        newly_created: bool = False,
    ):
        self.scan = scan
        self.cache_hit = cache_hit
        self.newly_created = newly_created
    
    @property
    def id(self) -> UUID:
        return self.scan.id
    
    @property
    def status(self) -> ScanStatus:
        return self.scan.status
    
    @property
    def full_image(self) -> str:
        return self.scan.full_image_name


class DashboardStats:
    """Aggregated statistics for the dashboard."""
    
    def __init__(
        self,
        total_scans: int,
        completed_scans: int,
        failed_scans: int,
        pending_scans: int,
        compliant_images: int,
        non_compliant_images: int,
        average_risk_score: float,
        top_risky_images: list[dict],
        compliance_rate: float,
        recent_scans: list[VulnerabilityScan],
    ):
        self.total_scans = total_scans
        self.completed_scans = completed_scans
        self.failed_scans = failed_scans
        self.pending_scans = pending_scans
        self.compliant_images = compliant_images
        self.non_compliant_images = non_compliant_images
        self.average_risk_score = average_risk_score
        self.top_risky_images = top_risky_images
        self.compliance_rate = compliance_rate
        self.recent_scans = recent_scans


# =============================================================================
# SCAN SERVICE - Core Business Logic
# =============================================================================

class ScanService:
    """
    Service class for vulnerability scan operations.
    
    Responsibilities:
    - Idempotency enforcement
    - Cache management
    - Background task coordination
    - Business rule validation
    
    Usage:
        async with get_db_session() as session:
            service = ScanService(session)
            result = await service.submit_scan_request("nginx:latest")
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize service with database session.
        
        Args:
            session: SQLAlchemy async session (injected via FastAPI dependency)
        """
        self.session = session
        self.scan_repo = ScanRepository(session)
        self.audit_repo = AuditLogRepository(session)
        
        # Configuration
        self.cache_ttl_minutes = settings.scan_cache_ttl_minutes
        self.max_retries = settings.scan_max_retries
    
    # =========================================================================
    # IMAGE NAME NORMALIZATION
    # =========================================================================
    
    @staticmethod
    def normalize_image_reference(
        image_name: str,
        image_tag: str | None = None,
        registry: str | None = None,
    ) -> tuple[str, str, str]:
        """
        Normalize image reference to canonical form.
        
        Handles various input formats:
        - "nginx" -> ("nginx", "latest", "docker.io")
        - "nginx:1.24" -> ("nginx", "1.24", "docker.io")
        - "gcr.io/project/image:v1" -> ("project/image", "v1", "gcr.io")
        
        Returns:
            Tuple of (image_name, image_tag, registry)
        """
        # Default values
        final_tag = image_tag or "latest"
        final_registry = registry or "docker.io"
        final_name = image_name.lower().strip("/")
        
        # Handle tag embedded in image name (nginx:1.24)
        if ":" in final_name and not image_tag:
            parts = final_name.rsplit(":", 1)
            final_name = parts[0]
            final_tag = parts[1] if len(parts) > 1 else "latest"
        
        # Handle registry embedded in image name (gcr.io/project/image)
        if "/" in final_name and not registry:
            first_part = final_name.split("/")[0]
            # Check if first part looks like a registry (contains "." or ":")
            if "." in first_part or ":" in first_part or first_part == "localhost":
                parts = final_name.split("/", 1)
                final_registry = parts[0]
                final_name = parts[1] if len(parts) > 1 else final_name
        
        return final_name, final_tag, final_registry
    
    # =========================================================================
    # SCAN RETRIEVAL
    # =========================================================================
    
    async def get_scan_by_id(self, scan_id: UUID) -> VulnerabilityScan:
        """
        Retrieve a scan by its ID.
        
        Args:
            scan_id: UUID of the scan
            
        Returns:
            VulnerabilityScan instance
            
        Raises:
            ScanNotFoundException: If scan doesn't exist
            DatabaseConnectionException: If database is unavailable
        """
        try:
            scan = await self.scan_repo.get_by_id(scan_id)
            
            if scan is None:
                logger.warning(f"Scan not found: {scan_id}")
                raise ScanNotFoundException(str(scan_id))
            
            return scan
            
        except SQLAlchemyError as e:
            logger.error(f"Database error fetching scan {scan_id}: {e}")
            raise DatabaseConnectionException(
                f"Failed to retrieve scan: {str(e)}"
            ) from e
    
    async def get_scan_status(self, scan_id: UUID) -> dict:
        """
        Get current scan status with progress information.
        
        Returns a lightweight status object suitable for polling.
        """
        scan = await self.get_scan_by_id(scan_id)
        
        return {
            "id": str(scan.id),
            "status": scan.status.value,
            "is_terminal": scan.is_terminal,
            "error_message": scan.error_message,
            "progress": self._calculate_progress(scan.status),
            "created_at": scan.created_at.isoformat(),
            "updated_at": scan.updated_at.isoformat(),
        }
    
    @staticmethod
    def _calculate_progress(status: ScanStatus) -> int:
        """Map scan status to progress percentage."""
        progress_map = {
            ScanStatus.PENDING: 0,
            ScanStatus.PULLING: 20,
            ScanStatus.SCANNING: 50,
            ScanStatus.PARSING: 80,
            ScanStatus.COMPLETED: 100,
            ScanStatus.FAILED: 100,
        }
        return progress_map.get(status, 0)
    
    # =========================================================================
    # IDEMPOTENT SCAN SUBMISSION - Core Logic
    # =========================================================================
    
    async def submit_scan_request(
        self,
        image_name: str,
        image_tag: str | None = None,
        registry: str | None = None,
        force_rescan: bool = False,
        background_tasks: BackgroundTasks | None = None,
        triggered_by: str | None = None,
    ) -> ScanResult:
        """
        Submit a scan request with idempotency handling.
        
        IDEMPOTENCY LOGIC:
        ==================
        1. Normalize the image reference (nginx -> nginx:latest)
        2. Check for COMPLETED scan within cache TTL (default 60 min)
        3. If found AND force=False: Return cached result (no new scan)
        4. If not found OR force=True: Create new scan, trigger worker
        
        Args:
            image_name: Docker image name (e.g., "nginx", "python")
            image_tag: Image tag (default: "latest")
            registry: Container registry (default: "docker.io")
            force_rescan: Bypass cache and force new scan
            background_tasks: FastAPI BackgroundTasks for async worker trigger
            triggered_by: User/system that initiated the request
            
        Returns:
            ScanResult with scan entity and cache_hit flag
            
        Raises:
            DatabaseConnectionException: If database is unavailable
            DatabaseTransactionException: If transaction fails
        """
        # Step 1: Normalize image reference
        norm_name, norm_tag, norm_registry = self.normalize_image_reference(
            image_name, image_tag, registry
        )
        full_image = f"{norm_registry}/{norm_name}:{norm_tag}"
        
        logger.info(f"Processing scan request for: {full_image} (force={force_rescan})")
        
        try:
            # Step 2: Check cache (unless force_rescan is True)
            if not force_rescan:
                cached_scan = await self._check_cache(
                    norm_name, norm_tag, norm_registry
                )
                
                if cached_scan:
                    logger.info(
                        f"Cache hit for {full_image}, returning scan {cached_scan.id}"
                    )
                    return ScanResult(
                        scan=cached_scan,
                        cache_hit=True,
                        newly_created=False,
                    )
            
            # Step 3: Check for in-progress scan (avoid duplicate work)
            in_progress = await self._check_in_progress(
                norm_name, norm_tag, norm_registry
            )
            
            if in_progress and not force_rescan:
                logger.info(
                    f"Scan already in progress for {full_image}: {in_progress.id}"
                )
                return ScanResult(
                    scan=in_progress,
                    cache_hit=False,
                    newly_created=False,
                )
            
            # Step 4: Create new scan
            new_scan = await self._create_scan(
                norm_name, norm_tag, norm_registry, triggered_by
            )
            
            logger.info(f"Created new scan {new_scan.id} for {full_image}")
            
            # Step 5: Trigger background worker
            if background_tasks:
                background_tasks.add_task(
                    trigger_worker_task,
                    scan_id=new_scan.id,
                )
                logger.debug(f"Queued background task for scan {new_scan.id}")
            
            return ScanResult(
                scan=new_scan,
                cache_hit=False,
                newly_created=True,
            )
            
        except SQLAlchemyError as e:
            logger.error(f"Database error during scan submission: {e}")
            raise DatabaseTransactionException(
                operation="scan_submission",
                reason=str(e),
            ) from e
    
    async def _check_cache(
        self,
        image_name: str,
        image_tag: str,
        registry: str,
    ) -> VulnerabilityScan | None:
        """
        Check if a valid cached scan exists.
        
        Cache Criteria:
        - Same image_name, image_tag, registry
        - Status = COMPLETED
        - Created within cache_ttl_minutes
        """
        return await self.scan_repo.find_cached_scan(
            image_name=image_name,
            image_tag=image_tag,
            registry=registry,
            max_age_minutes=self.cache_ttl_minutes,
        )
    
    async def _check_in_progress(
        self,
        image_name: str,
        image_tag: str,
        registry: str,
    ) -> VulnerabilityScan | None:
        """
        Check if a scan is already in progress for this image.
        
        In-Progress States: PENDING, PULLING, SCANNING, PARSING
        """
        from sqlalchemy import select, and_
        
        in_progress_states = [
            ScanStatus.PENDING,
            ScanStatus.PULLING,
            ScanStatus.SCANNING,
            ScanStatus.PARSING,
        ]
        
        stmt = (
            select(VulnerabilityScan)
            .where(
                and_(
                    VulnerabilityScan.image_name == image_name,
                    VulnerabilityScan.image_tag == image_tag,
                    VulnerabilityScan.registry == registry,
                    VulnerabilityScan.status.in_(in_progress_states),
                )
            )
            .limit(1)
        )
        
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def _create_scan(
        self,
        image_name: str,
        image_tag: str,
        registry: str,
        triggered_by: str | None = None,
    ) -> VulnerabilityScan:
        """
        Create a new scan record in PENDING state.
        """
        # Generate idempotency key
        idempotency_key = ScanRepository.generate_idempotency_key(
            image_name=image_name,
            image_tag=image_tag,
            registry=registry,
            cache_window_minutes=self.cache_ttl_minutes,
        )
        
        # Create scan entity
        scan = VulnerabilityScan(
            image_name=image_name,
            image_tag=image_tag,
            registry=registry,
            status=ScanStatus.PENDING,
            idempotency_key=idempotency_key,
        )
        
        # Persist to database
        scan = await self.scan_repo.create(scan)
        
        # Log audit trail
        await self.audit_repo.log_transition(
            scan_id=scan.id,
            previous_status=None,
            new_status=ScanStatus.PENDING,
            message="Scan request received",
            triggered_by=triggered_by or "api",
        )
        
        await self.session.commit()
        
        return scan
    
    # =========================================================================
    # SCAN LISTING & FILTERING
    # =========================================================================
    
    async def list_scans(
        self,
        page: int = 1,
        page_size: int = 20,
        status: ScanStatus | None = None,
        image_filter: str | None = None,
        compliant_only: bool = False,
    ) -> tuple[Sequence[VulnerabilityScan], int]:
        """
        List scans with filtering and pagination.
        
        Returns:
            Tuple of (scans list, total count)
        """
        try:
            return await self.scan_repo.list_scans(
                page=page,
                page_size=page_size,
                status_filter=status,
                image_name_filter=image_filter,
                compliant_only=compliant_only,
            )
        except SQLAlchemyError as e:
            logger.error(f"Database error listing scans: {e}")
            raise DatabaseConnectionException(
                f"Failed to list scans: {str(e)}"
            ) from e
    
    # =========================================================================
    # DASHBOARD ANALYTICS
    # =========================================================================
    
    async def get_dashboard_stats(self) -> DashboardStats:
        """
        Compute aggregated statistics for the dashboard.
        
        Returns:
            DashboardStats with counts, rates, and top risky images
        """
        try:
            # Get compliance summary
            compliance_summary = await self.scan_repo.get_compliance_summary()
            
            # Get all scans for counting (recent 30 days via view)
            all_scans, total = await self.scan_repo.list_scans(
                page=1,
                page_size=1000,  # Get enough for statistics
            )
            
            # Calculate counts
            completed = sum(1 for s in all_scans if s.status == ScanStatus.COMPLETED)
            failed = sum(1 for s in all_scans if s.status == ScanStatus.FAILED)
            pending = sum(
                1 for s in all_scans
                if s.status in [ScanStatus.PENDING, ScanStatus.PULLING, 
                                ScanStatus.SCANNING, ScanStatus.PARSING]
            )
            
            # Compliance counts (from completed scans only)
            completed_scans = [s for s in all_scans if s.status == ScanStatus.COMPLETED]
            compliant = sum(1 for s in completed_scans if s.is_compliant)
            non_compliant = len(completed_scans) - compliant
            
            # Average risk score
            if completed_scans:
                avg_risk = sum(s.risk_score for s in completed_scans) / len(completed_scans)
            else:
                avg_risk = 0.0
            
            # Compliance rate
            compliance_rate = (compliant / len(completed_scans) * 100) if completed_scans else 0.0
            
            # Get top risky images
            top_risky = await self.scan_repo.get_top_vulnerable_images(limit=5)
            top_risky_data = [
                {
                    "image": s.full_image_name,
                    "risk_score": s.risk_score,
                    "critical_count": s.critical_count,
                    "high_count": s.high_count,
                    "is_compliant": s.is_compliant,
                    "last_scanned": s.created_at.isoformat(),
                }
                for s in top_risky
            ]
            
            # Recent scans (last 10)
            recent, _ = await self.scan_repo.list_scans(page=1, page_size=10)
            
            return DashboardStats(
                total_scans=total,
                completed_scans=completed,
                failed_scans=failed,
                pending_scans=pending,
                compliant_images=compliant,
                non_compliant_images=non_compliant,
                average_risk_score=round(avg_risk, 2),
                top_risky_images=top_risky_data,
                compliance_rate=round(compliance_rate, 2),
                recent_scans=list(recent),
            )
            
        except SQLAlchemyError as e:
            logger.error(f"Database error computing dashboard stats: {e}")
            raise DatabaseConnectionException(
                f"Failed to compute dashboard stats: {str(e)}"
            ) from e
    
    async def get_image_trend(
        self,
        image_name: str,
        image_tag: str = "latest",
        days: int = 30,
    ) -> list[dict]:
        """
        Get vulnerability trend for a specific image over time.
        
        Returns list of data points for charting.
        """
        norm_name, norm_tag, _ = self.normalize_image_reference(image_name, image_tag)
        
        try:
            scans = await self.scan_repo.get_image_history(
                image_name=norm_name,
                image_tag=norm_tag,
                days=days,
            )
            
            return [
                {
                    "date": s.created_at.isoformat(),
                    "risk_score": s.risk_score,
                    "total_vulnerabilities": s.total_vulnerabilities,
                    "critical_count": s.critical_count,
                    "high_count": s.high_count,
                    "is_compliant": s.is_compliant,
                }
                for s in scans
            ]
            
        except SQLAlchemyError as e:
            logger.error(f"Database error fetching image trend: {e}")
            raise DatabaseConnectionException(
                f"Failed to fetch image trend: {str(e)}"
            ) from e


# =============================================================================
# BACKGROUND TASK - Worker Trigger
# =============================================================================

async def trigger_worker_task(scan_id: UUID) -> None:
    """
    Placeholder function to trigger the actual scan worker.
    
    In production, this would:
    1. Push message to Redis/RabbitMQ queue
    2. Or directly invoke the worker process
    3. Or call a Kubernetes Job API
    
    For now, we just log and import the worker when ready.
    """
    logger.info(f"[BACKGROUND TASK] Triggering worker for scan: {scan_id}")
    
    # TODO: In production, replace with actual queue/worker invocation
    # Example with Redis queue:
    #   await redis.rpush("scan_queue", str(scan_id))
    #
    # Example with direct worker call:
    #   from app.worker import ScanWorker
    #   worker = ScanWorker()
    #   await worker.process_scan(scan_id)
    
    try:
        # Import worker module (will be created in next step)
        from app.worker import process_scan_job
        await process_scan_job(scan_id)
    except ImportError:
        logger.warning(
            f"Worker module not yet available, scan {scan_id} will remain PENDING"
        )
    except Exception as e:
        logger.error(f"Worker task failed for scan {scan_id}: {e}")
