"""
Repository Pattern - Data Access Layer
======================================
Encapsulates all database queries for the vulnerability scanner.
Provides clean separation between business logic and data access.

Benefits:
- Testable (mock the repository, not the database)
- Cacheable (add Redis layer here)
- Optimizable (query tuning in one place)
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Sequence
from uuid import UUID

from sqlalchemy import select, func, desc, and_, or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    VulnerabilityScan,
    VulnerabilityDetail,
    ScanAuditLog,
    ScanStatus,
    ComplianceStatus,
)


class ScanRepository:
    """
    Repository for VulnerabilityScan operations.
    
    All database access for scans goes through this class.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    # =========================================================================
    # IDEMPOTENCY - Core deduplication logic
    # =========================================================================
    
    @staticmethod
    def generate_idempotency_key(
        image_name: str,
        image_tag: str,
        registry: str,
        cache_window_minutes: int = 60,
    ) -> str:
        """
        Generate idempotency key for deduplication.
        
        Logic:
        - Hash of (image_name + tag + registry + time_bucket)
        - time_bucket = floor(current_time / cache_window)
        - Ensures same image scanned within cache window returns same key
        
        Example:
        - nginx:latest at 10:15 -> bucket 10:00-11:00
        - nginx:latest at 10:45 -> same bucket, same key
        - nginx:latest at 11:05 -> new bucket, new key
        """
        # Calculate time bucket (floor division by cache window)
        now = datetime.now(timezone.utc)
        bucket_start = now.replace(
            minute=(now.minute // cache_window_minutes) * cache_window_minutes,
            second=0,
            microsecond=0,
        )
        bucket_str = bucket_start.strftime("%Y%m%d%H%M")
        
        # Create deterministic hash
        key_source = f"{registry}/{image_name}:{image_tag}:{bucket_str}"
        return hashlib.sha256(key_source.encode()).hexdigest()[:32]
    
    async def find_cached_scan(
        self,
        image_name: str,
        image_tag: str,
        registry: str,
        max_age_minutes: int = 60,
    ) -> VulnerabilityScan | None:
        """
        Find a recent completed scan for the same image.
        
        Used for idempotency - returns cached result instead of triggering new scan.
        
        Query Strategy:
        - Filter by image, tag, registry
        - Status must be COMPLETED
        - Created within max_age window
        - Order by created_at DESC, take first
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        
        stmt = (
            select(VulnerabilityScan)
            .where(
                and_(
                    VulnerabilityScan.image_name == image_name,
                    VulnerabilityScan.image_tag == image_tag,
                    VulnerabilityScan.registry == registry,
                    VulnerabilityScan.status == ScanStatus.COMPLETED,
                    VulnerabilityScan.created_at >= cutoff_time,
                )
            )
            .order_by(desc(VulnerabilityScan.created_at))
            .limit(1)
        )
        
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def find_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> VulnerabilityScan | None:
        """Find scan by idempotency key (exact match)."""
        stmt = select(VulnerabilityScan).where(
            VulnerabilityScan.idempotency_key == idempotency_key
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    # =========================================================================
    # CRUD OPERATIONS
    # =========================================================================
    
    async def create(self, scan: VulnerabilityScan) -> VulnerabilityScan:
        """Create new scan record."""
        self.session.add(scan)
        await self.session.flush()  # Get the generated ID
        await self.session.refresh(scan)
        return scan
    
    async def get_by_id(self, scan_id: UUID) -> VulnerabilityScan | None:
        """Get scan by primary key."""
        return await self.session.get(VulnerabilityScan, scan_id)
    
    async def update(self, scan: VulnerabilityScan) -> VulnerabilityScan:
        """Update existing scan (scan must be attached to session)."""
        await self.session.flush()
        await self.session.refresh(scan)
        return scan
    
    async def update_status(
        self,
        scan_id: UUID,
        new_status: ScanStatus,
        error_message: str | None = None,
        error_code: str | None = None,
    ) -> bool:
        """
        Atomic status update with optimistic locking pattern.
        
        Returns True if update succeeded, False if scan not found.
        """
        stmt = (
            update(VulnerabilityScan)
            .where(VulnerabilityScan.id == scan_id)
            .values(
                status=new_status,
                error_message=error_message,
                error_code=error_code,
                updated_at=datetime.now(timezone.utc),
            )
        )
        result = await self.session.execute(stmt)
        return result.rowcount > 0
    
    # =========================================================================
    # QUERY OPERATIONS
    # =========================================================================
    
    async def list_scans(
        self,
        page: int = 1,
        page_size: int = 20,
        status_filter: ScanStatus | None = None,
        image_name_filter: str | None = None,
        compliant_only: bool = False,
        order_by: str = "created_at",
        order_desc: bool = True,
    ) -> tuple[Sequence[VulnerabilityScan], int]:
        """
        List scans with filtering and pagination.
        
        Returns:
            Tuple of (scans list, total count)
        """
        # Base query
        query = select(VulnerabilityScan)
        count_query = select(func.count(VulnerabilityScan.id))
        
        # Apply filters
        filters = []
        if status_filter:
            filters.append(VulnerabilityScan.status == status_filter)
        if image_name_filter:
            # Case-insensitive LIKE search
            filters.append(VulnerabilityScan.image_name.ilike(f"%{image_name_filter}%"))
        if compliant_only:
            filters.append(VulnerabilityScan.is_compliant == True)
        
        if filters:
            query = query.where(and_(*filters))
            count_query = count_query.where(and_(*filters))
        
        # Get total count
        count_result = await self.session.execute(count_query)
        total = count_result.scalar() or 0
        
        # Apply ordering
        order_column = getattr(VulnerabilityScan, order_by, VulnerabilityScan.created_at)
        if order_desc:
            query = query.order_by(desc(order_column))
        else:
            query = query.order_by(order_column)
        
        # Apply pagination
        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)
        
        # Execute
        result = await self.session.execute(query)
        scans = result.scalars().all()
        
        return scans, total
    
    async def get_pending_scans(self, limit: int = 10) -> Sequence[VulnerabilityScan]:
        """
        Get pending scans for worker pickup.
        
        Orders by created_at to ensure FIFO processing.
        """
        stmt = (
            select(VulnerabilityScan)
            .where(VulnerabilityScan.status == ScanStatus.PENDING)
            .order_by(VulnerabilityScan.created_at)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_retry_candidates(
        self,
        max_retries: int = 3,
        limit: int = 10,
    ) -> Sequence[VulnerabilityScan]:
        """
        Get failed scans eligible for retry.
        
        Criteria:
        - Status = FAILED
        - retry_count < max_retries
        - Not a permanent failure (no specific error codes)
        """
        permanent_error_codes = ["INVALID_IMAGE", "AUTH_FAILED", "IMAGE_NOT_FOUND"]
        
        stmt = (
            select(VulnerabilityScan)
            .where(
                and_(
                    VulnerabilityScan.status == ScanStatus.FAILED,
                    VulnerabilityScan.retry_count < max_retries,
                    or_(
                        VulnerabilityScan.error_code.is_(None),
                        ~VulnerabilityScan.error_code.in_(permanent_error_codes),
                    ),
                )
            )
            .order_by(VulnerabilityScan.created_at)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    # =========================================================================
    # ANALYTICS QUERIES
    # =========================================================================
    
    async def get_image_history(
        self,
        image_name: str,
        image_tag: str,
        days: int = 30,
    ) -> Sequence[VulnerabilityScan]:
        """
        Get scan history for a specific image over time.
        
        Used for vulnerability trend analysis.
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        stmt = (
            select(VulnerabilityScan)
            .where(
                and_(
                    VulnerabilityScan.image_name == image_name,
                    VulnerabilityScan.image_tag == image_tag,
                    VulnerabilityScan.status == ScanStatus.COMPLETED,
                    VulnerabilityScan.created_at >= cutoff_date,
                )
            )
            .order_by(VulnerabilityScan.created_at)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_compliance_summary(self) -> dict:
        """
        Get aggregate compliance statistics.
        
        Returns counts of compliant, non-compliant, and pending review scans.
        """
        stmt = (
            select(
                VulnerabilityScan.compliance_status,
                func.count(VulnerabilityScan.id).label("count"),
            )
            .where(VulnerabilityScan.status == ScanStatus.COMPLETED)
            .group_by(VulnerabilityScan.compliance_status)
        )
        
        result = await self.session.execute(stmt)
        rows = result.all()
        
        return {row.compliance_status.value: row.count for row in rows}
    
    async def get_top_vulnerable_images(
        self,
        limit: int = 10,
    ) -> Sequence[VulnerabilityScan]:
        """
        Get images with highest risk scores.
        
        Returns latest scan for each unique image, ordered by risk score.
        """
        # Subquery to get latest scan ID for each image
        latest_scan_subq = (
            select(
                VulnerabilityScan.image_name,
                VulnerabilityScan.image_tag,
                func.max(VulnerabilityScan.created_at).label("max_created"),
            )
            .where(VulnerabilityScan.status == ScanStatus.COMPLETED)
            .group_by(VulnerabilityScan.image_name, VulnerabilityScan.image_tag)
            .subquery()
        )
        
        stmt = (
            select(VulnerabilityScan)
            .join(
                latest_scan_subq,
                and_(
                    VulnerabilityScan.image_name == latest_scan_subq.c.image_name,
                    VulnerabilityScan.image_tag == latest_scan_subq.c.image_tag,
                    VulnerabilityScan.created_at == latest_scan_subq.c.max_created,
                ),
            )
            .order_by(desc(VulnerabilityScan.risk_score))
            .limit(limit)
        )
        
        result = await self.session.execute(stmt)
        return result.scalars().all()


class VulnerabilityDetailRepository:
    """Repository for VulnerabilityDetail operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def bulk_create(
        self,
        details: list[VulnerabilityDetail],
    ) -> list[VulnerabilityDetail]:
        """Bulk insert vulnerability details."""
        self.session.add_all(details)
        await self.session.flush()
        return details
    
    async def find_by_cve(
        self,
        cve_id: str,
        limit: int = 100,
    ) -> Sequence[VulnerabilityDetail]:
        """
        Find all occurrences of a specific CVE across scans.
        
        Use Case: "Which images are affected by CVE-2024-XXXX?"
        """
        stmt = (
            select(VulnerabilityDetail)
            .where(VulnerabilityDetail.vulnerability_id == cve_id)
            .order_by(desc(VulnerabilityDetail.created_at))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_scan_details(
        self,
        scan_id: UUID,
    ) -> Sequence[VulnerabilityDetail]:
        """Get all vulnerability details for a scan."""
        stmt = (
            select(VulnerabilityDetail)
            .where(VulnerabilityDetail.scan_id == scan_id)
            .order_by(
                desc(VulnerabilityDetail.cvss_score),
                VulnerabilityDetail.severity,
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()


class AuditLogRepository:
    """Repository for ScanAuditLog operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def log_transition(
        self,
        scan_id: UUID,
        previous_status: ScanStatus | None,
        new_status: ScanStatus,
        message: str | None = None,
        metadata: dict | None = None,
        triggered_by: str | None = None,
    ) -> ScanAuditLog:
        """Log a scan state transition."""
        log = ScanAuditLog(
            scan_id=scan_id,
            previous_status=previous_status,
            new_status=new_status,
            message=message,
            metadata=metadata,
            triggered_by=triggered_by,
        )
        self.session.add(log)
        await self.session.flush()
        return log
    
    async def get_scan_history(
        self,
        scan_id: UUID,
    ) -> Sequence[ScanAuditLog]:
        """Get audit history for a scan."""
        stmt = (
            select(ScanAuditLog)
            .where(ScanAuditLog.scan_id == scan_id)
            .order_by(ScanAuditLog.created_at)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
