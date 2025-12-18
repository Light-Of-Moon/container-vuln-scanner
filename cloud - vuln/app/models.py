"""
SQLAlchemy ORM Models - High Intelligence Schema Design
========================================================
Principal Architecture Decisions:

1. HYBRID STORAGE PATTERN:
   - JSONB column for raw Trivy report (flexibility, full data retention)
   - Indexed scalar columns for "Intelligence Metrics" (query performance)
   
2. TEMPORAL DESIGN:
   - Composite index on (image_name, created_at) for historical trend queries
   - Partitioning-ready schema (by created_at month)
   
3. STATE MACHINE:
   - Scan lifecycle tracked via ScanStatus enum
   - State transitions logged for audit trail
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    Enum,
    Index,
    CheckConstraint,
    ForeignKey,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.ext.hybrid import hybrid_property

from app.database import Base


# =============================================================================
# ENUMS - Type-safe status tracking
# =============================================================================

class ScanStatus(str, enum.Enum):
    """
    Scan Lifecycle State Machine
    
    State Transitions:
        PENDING -> PULLING -> SCANNING -> PARSING -> COMPLETED
                     |           |           |
                     v           v           v
                   FAILED     FAILED      FAILED
    
    Terminal States: COMPLETED, FAILED
    """
    PENDING = "pending"       # Queued, waiting for worker
    PULLING = "pulling"       # Pulling Docker image
    SCANNING = "scanning"     # Trivy scan in progress
    PARSING = "parsing"       # Processing Trivy JSON output
    COMPLETED = "completed"   # Scan finished successfully
    FAILED = "failed"         # Scan failed (see error_message)


class SeverityLevel(str, enum.Enum):
    """CVSS Severity Classification (NVD standard)"""
    CRITICAL = "CRITICAL"  # CVSS 9.0-10.0
    HIGH = "HIGH"          # CVSS 7.0-8.9
    MEDIUM = "MEDIUM"      # CVSS 4.0-6.9
    LOW = "LOW"            # CVSS 0.1-3.9
    UNKNOWN = "UNKNOWN"    # No CVSS score available


class ComplianceStatus(str, enum.Enum):
    """
    Compliance classification based on vulnerability profile.
    
    Business Logic:
    - COMPLIANT: No Critical or High vulnerabilities
    - NON_COMPLIANT: Has Critical or High vulnerabilities
    - PENDING_REVIEW: Has only Medium/Low (needs manual review)
    """
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PENDING_REVIEW = "pending_review"


# =============================================================================
# CORE MODEL: VulnerabilityScan
# =============================================================================

class VulnerabilityScan(Base):
    """
    Primary entity for vulnerability scan results.
    
    Schema Design Rationale:
    --------------------------
    1. `raw_report` (JSONB): Stores complete Trivy JSON output
       - Preserves full audit trail
       - Enables future re-parsing with updated scoring algorithms
       - Supports ad-hoc queries via PostgreSQL JSONB operators
    
    2. Intelligence Metrics (Indexed Columns):
       - `risk_score`: Custom weighted score for prioritization
       - `critical_count`, `high_count`, etc.: Fast filtering
       - `is_compliant`: Boolean for compliance dashboards
       - `fixable_count`: Actionable vulnerability count
    
    3. Indexes:
       - Composite (image_name, created_at DESC): Historical trend queries
       - Single column indexes on filter columns
       - Partial index on failed scans for retry logic
    """
    
    __tablename__ = "vulnerability_scans"
    
    # ==========================================================================
    # PRIMARY KEY & IDENTIFIERS
    # ==========================================================================
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Unique scan identifier (UUIDv4)"
    )
    
    # Idempotency key - used for deduplication
    idempotency_key: Mapped[str | None] = mapped_column(
        String(64),
        unique=True,
        nullable=True,
        index=True,
        comment="Hash of (image_name + tag + timestamp_bucket) for deduplication"
    )
    
    # ==========================================================================
    # IMAGE IDENTIFICATION
    # ==========================================================================
    
    image_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Docker image name (e.g., 'nginx', 'python')"
    )
    
    image_tag: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default="latest",
        comment="Image tag (e.g., 'latest', '3.11-slim')"
    )
    
    image_digest: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="SHA256 digest for immutable identification"
    )
    
    registry: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="docker.io",
        comment="Container registry (e.g., 'docker.io', 'gcr.io')"
    )
    
    # ==========================================================================
    # SCAN LIFECYCLE STATE
    # ==========================================================================
    
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus),
        nullable=False,
        default=ScanStatus.PENDING,
        index=True,
        comment="Current scan state in lifecycle"
    )
    
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Error details if status=FAILED"
    )
    
    error_code: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Machine-readable error code (e.g., 'TIMEOUT', 'RATE_LIMIT')"
    )
    
    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of retry attempts"
    )
    
    # ==========================================================================
    # RAW SCAN DATA (JSONB)
    # ==========================================================================
    
    raw_report: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Complete Trivy JSON output (preserved for audit)"
    )
    
    # Metadata extracted from image
    image_metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Image labels, env vars, exposed ports (non-security metadata)"
    )
    
    # ==========================================================================
    # INTELLIGENCE METRICS (Indexed for Fast Queries)
    # ==========================================================================
    
    # Vulnerability counts by severity
    critical_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        index=True,
        comment="Count of CRITICAL severity CVEs"
    )
    
    high_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        index=True,
        comment="Count of HIGH severity CVEs"
    )
    
    medium_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of MEDIUM severity CVEs"
    )
    
    low_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of LOW severity CVEs"
    )
    
    unknown_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of UNKNOWN severity CVEs"
    )
    
    # Aggregated metrics
    total_vulnerabilities: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        index=True,
        comment="Total CVE count across all severities"
    )
    
    fixable_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        index=True,
        comment="CVEs with available patches/fixes"
    )
    
    unfixable_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="CVEs without available fixes"
    )
    
    # ==========================================================================
    # RISK SCORING
    # ==========================================================================
    
    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        index=True,
        comment="Weighted risk score: Critical=100, High=50, Medium=10, Low=1"
    )
    
    max_cvss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        index=True,
        comment="Highest CVSS score found in scan"
    )
    
    avg_cvss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Average CVSS score across all CVEs"
    )
    
    # ==========================================================================
    # COMPLIANCE FLAGS
    # ==========================================================================
    
    is_compliant: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="True if no Critical/High CVEs found"
    )
    
    compliance_status: Mapped[ComplianceStatus] = mapped_column(
        Enum(ComplianceStatus),
        nullable=False,
        default=ComplianceStatus.PENDING_REVIEW,
        index=True,
        comment="Detailed compliance classification"
    )
    
    # ==========================================================================
    # TIMING METRICS
    # ==========================================================================
    
    scan_duration: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        index=True,
        comment="Total scan duration in seconds"
    )
    
    pull_duration: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Image pull duration in seconds"
    )
    
    analysis_duration: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Trivy analysis duration in seconds"
    )
    
    # ==========================================================================
    # AUDIT TIMESTAMPS
    # ==========================================================================
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
        comment="Scan request timestamp"
    )
    
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Scan execution start timestamp"
    )
    
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Scan completion timestamp"
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Last update timestamp"
    )
    
    # ==========================================================================
    # WORKER METADATA
    # ==========================================================================
    
    worker_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Worker pod/instance that processed this scan"
    )
    
    trivy_version: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        comment="Trivy version used for scan"
    )
    
    # ==========================================================================
    # TABLE CONFIGURATION
    # ==========================================================================
    
    __table_args__ = (
        # Composite index for historical trend queries
        # "Show me all scans for nginx:latest over the past 30 days"
        Index(
            "ix_scans_image_history",
            "image_name",
            "image_tag",
            "created_at",
            postgresql_using="btree",
        ),
        
        # Composite index for compliance dashboards
        # "Show me all non-compliant images with critical vulnerabilities"
        Index(
            "ix_scans_compliance_filter",
            "is_compliant",
            "critical_count",
            "created_at",
            postgresql_using="btree",
        ),
        
        # Partial index for failed scans (retry queue)
        # Only indexes rows where status = 'failed' AND retry_count < 3
        Index(
            "ix_scans_retry_queue",
            "status",
            "retry_count",
            "created_at",
            postgresql_where=text("status = 'failed' AND retry_count < 3"),
        ),
        
        # Partial index for recent pending scans (worker pickup)
        Index(
            "ix_scans_pending_queue",
            "status",
            "created_at",
            postgresql_where=text("status = 'pending'"),
        ),
        
        # Check constraints for data integrity
        CheckConstraint(
            "risk_score >= 0",
            name="ck_risk_score_positive"
        ),
        CheckConstraint(
            "retry_count >= 0 AND retry_count <= 10",
            name="ck_retry_count_range"
        ),
        CheckConstraint(
            "critical_count >= 0 AND high_count >= 0 AND medium_count >= 0",
            name="ck_vuln_counts_positive"
        ),
        
        # Table comment
        {
            "comment": "Primary table for container vulnerability scan results"
        },
    )
    
    # ==========================================================================
    # HYBRID PROPERTIES (Computed at query/instance level)
    # ==========================================================================
    
    @hybrid_property
    def full_image_name(self) -> str:
        """Full image reference: registry/name:tag"""
        if self.registry and self.registry != "docker.io":
            return f"{self.registry}/{self.image_name}:{self.image_tag}"
        return f"{self.image_name}:{self.image_tag}"
    
    @hybrid_property
    def is_terminal(self) -> bool:
        """Check if scan is in a terminal state (no more updates expected)"""
        return self.status in (ScanStatus.COMPLETED, ScanStatus.FAILED)
    
    @hybrid_property
    def has_critical_vulnerabilities(self) -> bool:
        """Quick check for critical severity CVEs"""
        return self.critical_count > 0
    
    # ==========================================================================
    # INSTANCE METHODS
    # ==========================================================================
    
    def calculate_risk_score(self) -> int:
        """
        Calculate weighted risk score based on vulnerability counts.
        
        Scoring Formula (Defense University Standard):
        - Critical: 100 points each (immediate remediation required)
        - High: 50 points each (remediation within 7 days)
        - Medium: 10 points each (remediation within 30 days)
        - Low: 1 point each (best-effort remediation)
        """
        return (
            (self.critical_count * 100) +
            (self.high_count * 50) +
            (self.medium_count * 10) +
            (self.low_count * 1)
        )
    
    def determine_compliance_status(self) -> ComplianceStatus:
        """
        Determine compliance classification based on vulnerability profile.
        
        Business Rules:
        - COMPLIANT: Zero Critical AND Zero High
        - NON_COMPLIANT: Any Critical OR Any High
        - PENDING_REVIEW: Only Medium/Low (manual review needed)
        """
        if self.critical_count > 0 or self.high_count > 0:
            return ComplianceStatus.NON_COMPLIANT
        elif self.medium_count > 0 or self.low_count > 0:
            return ComplianceStatus.PENDING_REVIEW
        else:
            return ComplianceStatus.COMPLIANT
    
    def to_summary_dict(self) -> dict:
        """Export scan summary for API response"""
        return {
            "id": str(self.id),
            "image": self.full_image_name,
            "status": self.status.value,
            "risk_score": self.risk_score,
            "is_compliant": self.is_compliant,
            "vulnerability_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": self.total_vulnerabilities,
                "fixable": self.fixable_count,
            },
            "scan_duration": self.scan_duration,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
    
    def __repr__(self) -> str:
        return (
            f"<VulnerabilityScan("
            f"id={self.id}, "
            f"image={self.full_image_name}, "
            f"status={self.status.value}, "
            f"risk_score={self.risk_score}"
            f")>"
        )


# =============================================================================
# SUPPORTING MODEL: VulnerabilityDetail
# =============================================================================

class VulnerabilityDetail(Base):
    """
    Denormalized vulnerability details for fast queries.
    
    Design Rationale:
    - Extracted from JSONB for indexed querying
    - Enables "Find all images affected by CVE-2024-XXXX"
    - Supports vulnerability trending across all scans
    """
    
    __tablename__ = "vulnerability_details"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    
    # Foreign key to parent scan
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerability_scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # CVE identification
    vulnerability_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="CVE ID (e.g., 'CVE-2024-1234')"
    )
    
    # Affected package
    package_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Affected package name"
    )
    
    package_version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Installed package version"
    )
    
    fixed_version: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Version with fix (NULL if no fix available)"
    )
    
    # Severity
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel),
        nullable=False,
        index=True,
    )
    
    cvss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        index=True,
    )
    
    # Flags
    is_fixable: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )
    
    # Timestamps
    published_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="CVE publication date"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    
    __table_args__ = (
        # Composite index for CVE impact analysis
        Index(
            "ix_vuln_cve_lookup",
            "vulnerability_id",
            "severity",
        ),
        # Composite index for package analysis
        Index(
            "ix_vuln_package_lookup",
            "package_name",
            "package_version",
        ),
    )


# =============================================================================
# AUDIT MODEL: ScanAuditLog
# =============================================================================

class ScanAuditLog(Base):
    """
    Audit trail for scan state transitions.
    
    Purpose:
    - Compliance logging (who requested what, when)
    - Debugging failed scans
    - Performance analysis
    """
    
    __tablename__ = "scan_audit_logs"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerability_scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # State transition
    previous_status: Mapped[ScanStatus | None] = mapped_column(
        Enum(ScanStatus),
        nullable=True,
    )
    
    new_status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus),
        nullable=False,
    )
    
    # Context
    message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Additional context (worker info, error details)"
    )
    
    # Actor
    triggered_by: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="User or system that triggered the transition"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    
    __table_args__ = (
        Index(
            "ix_audit_scan_timeline",
            "scan_id",
            "created_at",
        ),
    )
