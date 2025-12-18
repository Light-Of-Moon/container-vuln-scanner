"""
Pydantic v2 Schemas - API Data Transfer Objects
================================================
Principal Architecture Decisions:

1. STRICT VALIDATION: All inputs validated before processing
2. COMPUTED FIELDS: Derived values calculated at serialization time
3. PARTIAL RESPONSES: Different schemas for list vs detail views
4. ENUM ALIGNMENT: Pydantic enums match SQLAlchemy enums exactly
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Annotated

from pydantic import (
    BaseModel,
    Field,
    ConfigDict,
    field_validator,
    field_serializer,
    computed_field,
    model_validator,
)


# =============================================================================
# ENUMS - Mirror SQLAlchemy enums for type safety
# =============================================================================

class ScanStatusEnum(str, enum.Enum):
    """Scan lifecycle states"""
    PENDING = "pending"
    PULLING = "pulling"
    SCANNING = "scanning"
    PARSING = "parsing"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityEnum(str, enum.Enum):
    """CVE severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ComplianceStatusEnum(str, enum.Enum):
    """Compliance classification"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PENDING_REVIEW = "pending_review"


# =============================================================================
# REQUEST SCHEMAS
# =============================================================================

class ScanRequest(BaseModel):
    """
    API request to initiate a vulnerability scan.
    
    Validation Rules:
    - image_name: Required, max 255 chars, must be valid Docker image format
    - image_tag: Optional (defaults to 'latest'), max 128 chars
    - registry: Optional (defaults to 'docker.io')
    - force_rescan: Bypass cache and force new scan (default: False)
    """
    
    model_config = ConfigDict(
        str_strip_whitespace=True,  # Auto-strip whitespace from strings
        str_min_length=1,           # No empty strings
        extra="forbid",             # Reject unknown fields (strict mode)
    )
    
    image_name: Annotated[str, Field(
        min_length=1,
        max_length=255,
        pattern=r'^[a-z0-9][a-z0-9._/-]*[a-z0-9]$|^[a-z0-9]$',
        examples=["nginx", "python", "gcr.io/project/image"],
        description="Docker image name (without tag)",
    )]
    
    image_tag: Annotated[str, Field(
        default="latest",
        max_length=128,
        pattern=r'^[\w][\w.-]{0,127}$',
        examples=["latest", "3.11-slim", "v1.2.3"],
        description="Image tag",
    )]
    
    registry: Annotated[str, Field(
        default="docker.io",
        max_length=255,
        examples=["docker.io", "gcr.io", "ghcr.io"],
        description="Container registry hostname",
    )]
    
    force_rescan: Annotated[bool, Field(
        default=False,
        description="Bypass cache and force new scan",
    )]
    
    @field_validator("image_name")
    @classmethod
    def validate_image_name(cls, v: str) -> str:
        """
        Normalize image name:
        - Strip leading/trailing slashes
        - Lowercase for consistency
        """
        return v.strip("/").lower()
    
    @field_validator("image_tag")
    @classmethod
    def validate_tag(cls, v: str) -> str:
        """Ensure tag doesn't start with special characters"""
        if v.startswith(("-", ".")):
            raise ValueError("Tag cannot start with '-' or '.'")
        return v
    
    @computed_field
    @property
    def full_image_reference(self) -> str:
        """Computed full image reference for display"""
        if self.registry != "docker.io":
            return f"{self.registry}/{self.image_name}:{self.image_tag}"
        return f"{self.image_name}:{self.image_tag}"


class ScanBatchRequest(BaseModel):
    """
    Batch scan request for multiple images.
    
    Use Case: CI/CD pipeline scanning multiple base images
    Limit: Max 50 images per batch to prevent DoS
    """
    
    model_config = ConfigDict(extra="forbid")
    
    images: Annotated[list[ScanRequest], Field(
        min_length=1,
        max_length=50,
        description="List of images to scan (max 50)",
    )]
    
    priority: Annotated[int, Field(
        default=5,
        ge=1,
        le=10,
        description="Queue priority (1=lowest, 10=highest)",
    )]


# =============================================================================
# RESPONSE SCHEMAS - Nested Components
# =============================================================================

class VulnerabilityCountsSchema(BaseModel):
    """Breakdown of vulnerabilities by severity"""
    
    model_config = ConfigDict(from_attributes=True)
    
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    unknown: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)
    fixable: int = Field(default=0, ge=0)
    unfixable: int = Field(default=0, ge=0)
    
    @computed_field
    @property
    def critical_and_high(self) -> int:
        """Combined count of Critical + High (compliance metric)"""
        return self.critical + self.high
    
    @computed_field
    @property
    def fixable_ratio(self) -> float:
        """Percentage of vulnerabilities that are fixable"""
        if self.total == 0:
            return 1.0  # No vulns = 100% fixable (nothing to fix)
        return round(self.fixable / self.total, 4)


class ScanTimingSchema(BaseModel):
    """Timing metrics for scan performance analysis"""
    
    model_config = ConfigDict(from_attributes=True)
    
    scan_duration: float | None = Field(
        default=None,
        description="Total scan duration (seconds)",
    )
    pull_duration: float | None = Field(
        default=None,
        description="Image pull duration (seconds)",
    )
    analysis_duration: float | None = Field(
        default=None,
        description="Trivy analysis duration (seconds)",
    )
    
    @computed_field
    @property
    def overhead_duration(self) -> float | None:
        """Time spent on non-core operations (queue wait, parsing)"""
        if self.scan_duration is None:
            return None
        core = (self.pull_duration or 0) + (self.analysis_duration or 0)
        return round(self.scan_duration - core, 3)


class RiskAssessmentSchema(BaseModel):
    """Risk scoring and compliance assessment"""
    
    model_config = ConfigDict(from_attributes=True)
    
    risk_score: int = Field(
        default=0,
        ge=0,
        description="Weighted risk score (Critical=100, High=50, Medium=10, Low=1)",
    )
    max_cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Highest CVSS score found",
    )
    avg_cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Average CVSS score",
    )
    is_compliant: bool = Field(
        default=False,
        description="True if no Critical/High vulnerabilities",
    )
    compliance_status: ComplianceStatusEnum = Field(
        default=ComplianceStatusEnum.PENDING_REVIEW,
        description="Detailed compliance classification",
    )
    
    @computed_field
    @property
    def risk_level(self) -> str:
        """
        Human-readable risk level based on score.
        
        Thresholds (Defense University Standard):
        - CRITICAL: score >= 500 (5+ critical vulns or 10+ high)
        - HIGH: score >= 100 (1+ critical or 2+ high)
        - MEDIUM: score >= 30 (3+ medium)
        - LOW: score > 0
        - NONE: score = 0
        """
        if self.risk_score >= 500:
            return "CRITICAL"
        elif self.risk_score >= 100:
            return "HIGH"
        elif self.risk_score >= 30:
            return "MEDIUM"
        elif self.risk_score > 0:
            return "LOW"
        return "NONE"
    
    @computed_field
    @property
    def remediation_urgency(self) -> str:
        """
        Recommended remediation timeline based on risk level.
        """
        mapping = {
            "CRITICAL": "Immediate (within 24 hours)",
            "HIGH": "Urgent (within 7 days)",
            "MEDIUM": "Standard (within 30 days)",
            "LOW": "Best-effort (within 90 days)",
            "NONE": "No action required",
        }
        return mapping.get(self.risk_level, "Unknown")


class VulnerabilityDetailSchema(BaseModel):
    """Individual vulnerability details (from denormalized table)"""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: uuid.UUID
    vulnerability_id: str = Field(
        description="CVE identifier (e.g., CVE-2024-1234)",
    )
    package_name: str
    package_version: str
    fixed_version: str | None = Field(
        default=None,
        description="Version with fix (null if no fix)",
    )
    severity: SeverityEnum
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    is_fixable: bool = Field(default=False)
    published_date: datetime | None = None
    
    @computed_field
    @property
    def upgrade_path(self) -> str | None:
        """Formatted upgrade recommendation"""
        if self.fixed_version:
            return f"{self.package_name}: {self.package_version} → {self.fixed_version}"
        return None


# =============================================================================
# RESPONSE SCHEMAS - Main API Responses
# =============================================================================

class ScanSummaryResponse(BaseModel):
    """
    Compact scan summary for list views and quick lookups.
    
    Use Case:
    - GET /scans (list all scans)
    - Dashboard cards
    - CI/CD webhook responses
    """
    
    model_config = ConfigDict(from_attributes=True)
    
    id: uuid.UUID = Field(description="Unique scan identifier")
    
    # Image identification
    image_name: str
    image_tag: str
    registry: str
    
    # Status
    status: ScanStatusEnum
    error_message: str | None = None
    
    # Key metrics (flattened for easy access)
    risk_score: int = Field(default=0)
    is_compliant: bool = Field(default=False)
    total_vulnerabilities: int = Field(default=0)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    fixable_count: int = Field(default=0)
    
    # Timing
    scan_duration: float | None = None
    created_at: datetime
    completed_at: datetime | None = None
    
    @computed_field
    @property
    def full_image(self) -> str:
        """Full image reference"""
        if self.registry != "docker.io":
            return f"{self.registry}/{self.image_name}:{self.image_tag}"
        return f"{self.image_name}:{self.image_tag}"
    
    @computed_field
    @property
    def status_emoji(self) -> str:
        """Status indicator for dashboards"""
        mapping = {
            ScanStatusEnum.PENDING: "⏳",
            ScanStatusEnum.PULLING: "📥",
            ScanStatusEnum.SCANNING: "🔍",
            ScanStatusEnum.PARSING: "📊",
            ScanStatusEnum.COMPLETED: "✅",
            ScanStatusEnum.FAILED: "❌",
        }
        return mapping.get(self.status, "❓")
    
    @field_serializer("created_at", "completed_at")
    def serialize_datetime(self, dt: datetime | None) -> str | None:
        """ISO format datetime serialization"""
        return dt.isoformat() if dt else None


class ScanDetailResponse(BaseModel):
    """
    Full scan details including all metrics and raw data.
    
    Use Case:
    - GET /scans/{id} (single scan detail)
    - Detailed compliance reports
    """
    
    model_config = ConfigDict(from_attributes=True)
    
    id: uuid.UUID
    idempotency_key: str | None = None
    
    # Image identification
    image_name: str
    image_tag: str
    image_digest: str | None = None
    registry: str
    
    # Status
    status: ScanStatusEnum
    error_message: str | None = None
    error_code: str | None = None
    retry_count: int = Field(default=0)
    
    # Nested metrics
    vulnerability_counts: VulnerabilityCountsSchema
    risk_assessment: RiskAssessmentSchema
    timing: ScanTimingSchema
    
    # Metadata
    worker_id: str | None = None
    trivy_version: str | None = None
    
    # Timestamps
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    updated_at: datetime
    
    # Raw data (only included if requested)
    raw_report: dict | None = Field(
        default=None,
        description="Full Trivy JSON output (large payload)",
    )
    
    @model_validator(mode="before")
    @classmethod
    def build_nested_objects(cls, data: Any) -> Any:
        """
        Transform flat ORM model attributes into nested schema objects.
        
        This handles the mapping from:
            VulnerabilityScan.critical_count -> VulnerabilityCountsSchema.critical
        """
        if hasattr(data, "__dict__"):
            # SQLAlchemy model - convert to dict-like access
            return {
                "id": data.id,
                "idempotency_key": data.idempotency_key,
                "image_name": data.image_name,
                "image_tag": data.image_tag,
                "image_digest": data.image_digest,
                "registry": data.registry,
                "status": data.status,
                "error_message": data.error_message,
                "error_code": data.error_code,
                "retry_count": data.retry_count,
                "vulnerability_counts": {
                    "critical": data.critical_count,
                    "high": data.high_count,
                    "medium": data.medium_count,
                    "low": data.low_count,
                    "unknown": data.unknown_count,
                    "total": data.total_vulnerabilities,
                    "fixable": data.fixable_count,
                    "unfixable": data.unfixable_count,
                },
                "risk_assessment": {
                    "risk_score": data.risk_score,
                    "max_cvss_score": data.max_cvss_score,
                    "avg_cvss_score": data.avg_cvss_score,
                    "is_compliant": data.is_compliant,
                    "compliance_status": data.compliance_status,
                },
                "timing": {
                    "scan_duration": data.scan_duration,
                    "pull_duration": data.pull_duration,
                    "analysis_duration": data.analysis_duration,
                },
                "worker_id": data.worker_id,
                "trivy_version": data.trivy_version,
                "created_at": data.created_at,
                "started_at": data.started_at,
                "completed_at": data.completed_at,
                "updated_at": data.updated_at,
                "raw_report": data.raw_report,
            }
        return data
    
    @computed_field
    @property
    def full_image(self) -> str:
        """Full image reference"""
        if self.registry != "docker.io":
            return f"{self.registry}/{self.image_name}:{self.image_tag}"
        return f"{self.image_name}:{self.image_tag}"


class ScanCreatedResponse(BaseModel):
    """
    Response when a new scan is created (or cached result returned).
    
    Includes cache_hit flag to inform client if result is from cache.
    """
    
    id: uuid.UUID
    status: ScanStatusEnum
    full_image: str
    cache_hit: bool = Field(
        default=False,
        description="True if result returned from cache (no new scan triggered)",
    )
    cached_at: datetime | None = Field(
        default=None,
        description="Original scan timestamp (if cache_hit=True)",
    )
    message: str = Field(
        default="Scan queued successfully",
        description="Status message",
    )
    
    @computed_field
    @property
    def poll_url(self) -> str:
        """URL to poll for status updates"""
        return f"/api/v1/scans/{self.id}"


# =============================================================================
# PAGINATION & LIST RESPONSES
# =============================================================================

class PaginationMeta(BaseModel):
    """Pagination metadata for list responses"""
    
    total: int = Field(ge=0, description="Total number of items")
    page: int = Field(ge=1, description="Current page number")
    page_size: int = Field(ge=1, le=100, description="Items per page")
    total_pages: int = Field(ge=0, description="Total number of pages")
    has_next: bool = Field(description="More pages available")
    has_prev: bool = Field(description="Previous pages available")


class ScanListResponse(BaseModel):
    """Paginated list of scan summaries"""
    
    items: list[ScanSummaryResponse]
    pagination: PaginationMeta
    
    @computed_field
    @property
    def compliant_count(self) -> int:
        """Count of compliant scans in this page"""
        return sum(1 for item in self.items if item.is_compliant)
    
    @computed_field
    @property
    def avg_risk_score(self) -> float:
        """Average risk score for this page"""
        if not self.items:
            return 0.0
        return round(sum(i.risk_score for i in self.items) / len(self.items), 2)


# =============================================================================
# TREND & ANALYTICS SCHEMAS
# =============================================================================

class VulnerabilityTrendPoint(BaseModel):
    """Single data point in a vulnerability trend"""
    
    date: datetime
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    risk_score: int
    is_compliant: bool


class ImageTrendResponse(BaseModel):
    """
    Vulnerability trend over time for a specific image.
    
    Use Case: "Show me the security posture of nginx:latest over the past 30 days"
    """
    
    image_name: str
    image_tag: str
    data_points: list[VulnerabilityTrendPoint]
    
    @computed_field
    @property
    def trend_direction(self) -> str:
        """
        Calculate if security posture is improving or degrading.
        
        Logic: Compare first and last data points' risk scores
        """
        if len(self.data_points) < 2:
            return "INSUFFICIENT_DATA"
        
        first_score = self.data_points[0].risk_score
        last_score = self.data_points[-1].risk_score
        
        if last_score < first_score:
            return "IMPROVING"
        elif last_score > first_score:
            return "DEGRADING"
        return "STABLE"
    
    @computed_field
    @property
    def average_risk_score(self) -> float:
        """Average risk score across all data points"""
        if not self.data_points:
            return 0.0
        return round(
            sum(dp.risk_score for dp in self.data_points) / len(self.data_points),
            2
        )


# =============================================================================
# ERROR SCHEMAS
# =============================================================================

class ErrorDetail(BaseModel):
    """Structured error detail"""
    
    code: str = Field(description="Machine-readable error code")
    message: str = Field(description="Human-readable error message")
    field: str | None = Field(default=None, description="Field that caused error")
    details: dict | None = Field(default=None, description="Additional context")


class ErrorResponse(BaseModel):
    """Standard API error response"""
    
    status: str = Field(default="error")
    error: ErrorDetail
    request_id: str | None = Field(
        default=None,
        description="Request ID for tracing",
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# HEALTH CHECK SCHEMAS
# =============================================================================

class HealthCheckResponse(BaseModel):
    """API health check response"""
    
    status: str = Field(description="Overall health status")
    version: str = Field(description="API version")
    database: str = Field(description="Database connection status")
    worker: str = Field(description="Worker queue status")
    uptime_seconds: float = Field(description="Service uptime")
    
    @computed_field
    @property
    def is_healthy(self) -> bool:
        """Quick boolean health check"""
        return self.status == "healthy" and self.database == "connected"
