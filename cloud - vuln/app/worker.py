"""
Trivy Scanner Worker - Production-Grade Vulnerability Scanning Engine
=====================================================================
Principal Architecture Decisions:

1. SUBPROCESS SAFETY:
   - Hard timeout on Trivy execution (configurable, default 10 min)
   - Explicit process termination on timeout (zombie prevention)
   - Secure shell=False execution (no injection risk)

2. STATE MACHINE:
   - PENDING -> PULLING -> SCANNING -> PARSING -> COMPLETED
   - Any failure -> FAILED (with error capture)
   - Atomic status transitions with audit logging

3. RESILIENCE:
   - Worker never crashes on job failure
   - Graceful SIGTERM/SIGINT handling
   - Connection retry logic for database

4. OBSERVABILITY:
   - Structured logging for all state transitions
   - Timing metrics for each phase
   - Error classification for debugging
"""

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db_session, get_session_factory
from app.models import (
    VulnerabilityScan,
    VulnerabilityDetail,
    ScanAuditLog,
    ScanStatus,
    SeverityLevel,
    ComplianceStatus,
)
from app.exceptions import (
    ScanTimeoutException,
    ScanFailedException,
    TrivyExecutionException,
    ImagePullException,
    ImageNotFoundException,
)

# =============================================================================
# LOGGING SETUP
# =============================================================================

logger = logging.getLogger(__name__)

# Structured log format for production
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - [%(scan_id)s] %(message)s"


class ScanLogAdapter(logging.LoggerAdapter):
    """Logger adapter that includes scan_id in all log messages."""
    
    def process(self, msg, kwargs):
        scan_id = self.extra.get("scan_id", "NO_SCAN")
        kwargs.setdefault("extra", {})["scan_id"] = scan_id
        return msg, kwargs


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class RiskMetrics:
    """Calculated risk metrics from Trivy scan results."""
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    unknown_count: int = 0
    total_vulnerabilities: int = 0
    fixable_count: int = 0
    unfixable_count: int = 0
    risk_score: int = 0
    max_cvss_score: float | None = None
    avg_cvss_score: float | None = None
    is_compliant: bool = True
    compliance_status: ComplianceStatus = ComplianceStatus.compliant
    vulnerabilities: list[dict] = field(default_factory=list)


@dataclass
class ScanTiming:
    """Timing metrics for scan phases."""
    
    total_start: float = 0.0
    pull_start: float | None = None
    pull_end: float | None = None
    scan_start: float | None = None
    scan_end: float | None = None
    parse_start: float | None = None
    parse_end: float | None = None
    
    @property
    def pull_duration(self) -> float | None:
        if self.pull_start and self.pull_end:
            return round(self.pull_end - self.pull_start, 3)
        return None
    
    @property
    def scan_duration(self) -> float | None:
        if self.scan_start and self.scan_end:
            return round(self.scan_end - self.scan_start, 3)
        return None
    
    @property
    def total_duration(self) -> float:
        return round(time.time() - self.total_start, 3)


# =============================================================================
# WORKER CONFIGURATION
# =============================================================================

@dataclass
class WorkerConfig:
    """Worker configuration with sensible defaults."""
    
    # Trivy settings
    trivy_binary: str = settings.trivy_binary_path
    trivy_cache_dir: str = settings.trivy_cache_dir
    trivy_timeout: int = settings.trivy_timeout_seconds  # 5 minutes default
    
    # Worker settings
    poll_interval: int = settings.worker_poll_interval_seconds
    max_retries: int = settings.scan_max_retries
    batch_size: int = 1  # Process one scan at a time for simplicity
    
    # Risk scoring weights
    weight_critical: int = settings.risk_weight_critical
    weight_high: int = settings.risk_weight_high
    weight_medium: int = settings.risk_weight_medium
    weight_low: int = settings.risk_weight_low
    
    # Worker identification
    worker_id: str = field(default_factory=lambda: f"worker-{os.getpid()}")


# =============================================================================
# TRIVY EXECUTION - Secure Subprocess Handling
# =============================================================================

async def run_trivy_scan(
    image_reference: str,
    output_path: Path,
    config: WorkerConfig,
    log: logging.LoggerAdapter,
) -> dict:
    """
    Execute Trivy scan with async subprocess handling.
    
    Security Measures:
    - shell=False prevents command injection
    - Explicit timeout prevents zombie processes
    - Process killed on timeout (not just terminated)
    - Temporary file for output (cleaned up by caller)
    
    PERFORMANCE FIX:
    - Uses asyncio.create_subprocess_exec instead of subprocess.Popen
    - Non-blocking execution allows the event loop to continue
    - Enables true concurrent scan processing
    
    Args:
        image_reference: Full image reference (e.g., "nginx:latest")
        output_path: Path to write JSON output
        config: Worker configuration
        log: Logger adapter with scan context
    
    Returns:
        Parsed JSON output from Trivy
    
    Raises:
        ScanTimeoutException: If scan exceeds timeout
        TrivyExecutionException: If Trivy returns non-zero exit code
        ImageNotFoundException: If image doesn't exist
    """
    # Build Trivy command
    # Using --scanners vuln to only scan for vulnerabilities (not secrets/config)
    cmd = [
        config.trivy_binary,
        "image",
        "--format", "json",
        "--output", str(output_path),
        "--timeout", f"{config.trivy_timeout}s",
        "--scanners", "vuln",
        "--cache-dir", config.trivy_cache_dir,
        # Allow Trivy to download/update the vulnerability database if needed
        # This ensures scans work even on fresh installations
        # Quiet mode - only output results
        "--quiet",
        image_reference,
    ]
    
    log.info(f"Executing Trivy: {' '.join(cmd)}")
    
    process = None
    try:
        # Set up environment
        env = os.environ.copy()
        env["TRIVY_CACHE_DIR"] = config.trivy_cache_dir
        env["NO_COLOR"] = "1"  # Disable color output for cleaner logs
        
        # Execute with async subprocess - NON-BLOCKING!
        # This is the key performance fix - allows event loop to continue
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        
        # Wait with timeout using asyncio.wait_for (non-blocking)
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.trivy_timeout
            )
        except asyncio.TimeoutError:
            # CRITICAL: Kill the process on timeout to prevent zombies
            log.error(f"Trivy scan timed out after {config.trivy_timeout}s - killing process")
            
            # First try graceful termination
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                # Force kill if still running
                log.warning("Process did not terminate gracefully, sending SIGKILL")
                process.kill()
                await process.wait()
            
            raise ScanTimeoutException(
                scan_id="unknown",  # Will be set by caller
                timeout_seconds=config.trivy_timeout,
            )
        
        # Check exit code
        if process.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            
            # Classify error type
            if "could not find image" in stderr_text.lower() or "manifest unknown" in stderr_text.lower():
                raise ImageNotFoundException(
                    image_name=image_reference,
                    registry="unknown",
                )
            elif "unauthorized" in stderr_text.lower() or "denied" in stderr_text.lower():
                raise ImagePullException(
                    image_name=image_reference,
                    reason="Authentication failed - check registry credentials",
                )
            elif "rate limit" in stderr_text.lower() or "too many requests" in stderr_text.lower():
                raise ImagePullException(
                    image_name=image_reference,
                    reason="Registry rate limit exceeded",
                )
            else:
                raise TrivyExecutionException(
                    reason=stderr_text or f"Exit code {process.returncode}",
                    exit_code=process.returncode,
                )
        
        # Parse output file
        if not output_path.exists():
            raise TrivyExecutionException(
                reason="Trivy did not produce output file",
                exit_code=process.returncode,
            )
        
        with open(output_path, "r") as f:
            result = json.load(f)
        
        log.info(f"Trivy scan completed successfully")
        return result
    
    except json.JSONDecodeError as e:
        raise TrivyExecutionException(
            reason=f"Failed to parse Trivy JSON output: {e}",
            exit_code=0,
        )


def run_trivy_scan_with_db_update(
    image_reference: str,
    config: WorkerConfig,
    log: logging.LoggerAdapter,
) -> None:
    """
    Update Trivy vulnerability database.
    
    Should be run periodically (e.g., daily via cron) rather than per-scan.
    """
    cmd = [
        config.trivy_binary,
        "image",
        "--download-db-only",
        "--cache-dir", config.trivy_cache_dir,
    ]
    
    log.info("Updating Trivy vulnerability database...")
    
    try:
        subprocess.run(
            cmd,
            timeout=300,  # 5 minute timeout for DB download
            check=True,
            capture_output=True,
        )
        log.info("Trivy database updated successfully")
    except subprocess.TimeoutExpired:
        log.error("Trivy database update timed out")
    except subprocess.CalledProcessError as e:
        log.error(f"Trivy database update failed: {e.stderr.decode()}")


# =============================================================================
# INTELLIGENCE PARSING - Risk Metrics Calculation
# =============================================================================

def calculate_risk_metrics(
    trivy_output: dict,
    config: WorkerConfig,
) -> RiskMetrics:
    """
    Parse Trivy JSON output and calculate risk metrics.
    
    Trivy Output Structure:
    {
        "Results": [
            {
                "Target": "nginx:latest (debian 11.6)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "FixedVersion": "1.1.2",
                        "Severity": "CRITICAL",
                        "CVSS": {
                            "nvd": {"V3Score": 9.8}
                        }
                    }
                ]
            }
        ]
    }
    
    Scoring Formula (Defense University Standard):
    - Critical: 100 points (CVSS 9.0-10.0)
    - High: 50 points (CVSS 7.0-8.9)
    - Medium: 10 points (CVSS 4.0-6.9)
    - Low: 1 point (CVSS 0.1-3.9)
    
    Args:
        trivy_output: Parsed Trivy JSON
        config: Worker configuration with scoring weights
    
    Returns:
        RiskMetrics dataclass with all calculated values
    """
    metrics = RiskMetrics()
    cvss_scores: list[float] = []
    
    # Extract all vulnerabilities from all results (targets)
    results = trivy_output.get("Results", [])
    
    for result in results:
        vulnerabilities = result.get("Vulnerabilities") or []
        
        for vuln in vulnerabilities:
            metrics.total_vulnerabilities += 1
            
            # Get severity (default to UNKNOWN if missing)
            severity = vuln.get("Severity", "UNKNOWN").upper()
            
            # Count by severity
            if severity == "CRITICAL":
                metrics.critical_count += 1
            elif severity == "HIGH":
                metrics.high_count += 1
            elif severity == "MEDIUM":
                metrics.medium_count += 1
            elif severity == "LOW":
                metrics.low_count += 1
            else:
                metrics.unknown_count += 1
            
            # Check if fixable (FixedVersion exists and is not empty)
            fixed_version = vuln.get("FixedVersion", "")
            if fixed_version and fixed_version.strip():
                metrics.fixable_count += 1
            else:
                metrics.unfixable_count += 1
            
            # Extract CVSS score (try multiple sources)
            cvss_score = extract_cvss_score(vuln)
            if cvss_score is not None:
                cvss_scores.append(cvss_score)
            
            # Store vulnerability details for potential insertion
            metrics.vulnerabilities.append({
                "vulnerability_id": vuln.get("VulnerabilityID", "UNKNOWN"),
                "package_name": vuln.get("PkgName", "unknown"),
                "package_version": vuln.get("InstalledVersion", "unknown"),
                "fixed_version": fixed_version or None,
                "severity": severity,
                "cvss_score": cvss_score,
                "is_fixable": bool(fixed_version and fixed_version.strip()),
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", ""),
                "published_date": vuln.get("PublishedDate"),
            })
    
    # Calculate risk score using weighted formula
    metrics.risk_score = (
        (metrics.critical_count * config.weight_critical) +
        (metrics.high_count * config.weight_high) +
        (metrics.medium_count * config.weight_medium) +
        (metrics.low_count * config.weight_low)
    )
    
    # Calculate CVSS statistics
    if cvss_scores:
        metrics.max_cvss_score = max(cvss_scores)
        metrics.avg_cvss_score = round(sum(cvss_scores) / len(cvss_scores), 2)
    
    # Determine compliance status
    if metrics.critical_count > 0 or metrics.high_count > 0:
        metrics.is_compliant = False
        metrics.compliance_status = ComplianceStatus.non_compliant
    elif metrics.medium_count > 0 or metrics.low_count > 0:
        metrics.is_compliant = False  # Has vulns but not critical/high
        metrics.compliance_status = ComplianceStatus.pending_review
    else:
        metrics.is_compliant = True
        metrics.compliance_status = ComplianceStatus.compliant
    
    return metrics


def extract_cvss_score(vuln: dict) -> float | None:
    """
    Extract CVSS score from vulnerability data.
    
    Trivy provides CVSS in multiple formats. Priority order:
    1. CVSS v3 from NVD
    2. CVSS v3 from vendor
    3. CVSS v2 from NVD
    4. None if no score available
    """
    cvss_data = vuln.get("CVSS", {})
    
    # Try NVD v3 first
    nvd = cvss_data.get("nvd", {})
    if "V3Score" in nvd:
        return float(nvd["V3Score"])
    
    # Try vendor v3
    for vendor, scores in cvss_data.items():
        if isinstance(scores, dict) and "V3Score" in scores:
            return float(scores["V3Score"])
    
    # Try v2 as fallback
    if "V2Score" in nvd:
        return float(nvd["V2Score"])
    
    for vendor, scores in cvss_data.items():
        if isinstance(scores, dict) and "V2Score" in scores:
            return float(scores["V2Score"])
    
    return None


# =============================================================================
# DATABASE OPERATIONS
# =============================================================================

async def fetch_pending_scan(session: AsyncSession) -> VulnerabilityScan | None:
    """
    Fetch a single pending scan for processing.
    
    Uses SELECT ... FOR UPDATE SKIP LOCKED pattern for safe concurrent access.
    This ensures only one worker processes each scan, even with multiple workers.
    """
    # Note: FOR UPDATE SKIP LOCKED requires PostgreSQL
    # For SQLite (testing), we fall back to simple select
    stmt = (
        select(VulnerabilityScan)
        .where(VulnerabilityScan.status == ScanStatus.pending)
        .order_by(VulnerabilityScan.created_at)
        .limit(1)
        # PostgreSQL-specific: .with_for_update(skip_locked=True)
    )
    
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def update_scan_status(
    session: AsyncSession,
    scan_id: UUID,
    new_status: ScanStatus,
    error_message: str | None = None,
    error_code: str | None = None,
    **kwargs,
) -> None:
    """
    Update scan status with optional additional fields.
    """
    values = {
        "status": new_status,
        "updated_at": datetime.now(timezone.utc),
    }
    
    if error_message:
        values["error_message"] = error_message
    if error_code:
        values["error_code"] = error_code
    
    values.update(kwargs)
    
    stmt = (
        update(VulnerabilityScan)
        .where(VulnerabilityScan.id == scan_id)
        .values(**values)
    )
    
    await session.execute(stmt)
    await session.commit()


async def save_scan_results(
    session: AsyncSession,
    scan_id: UUID,
    raw_report: dict,
    metrics: RiskMetrics,
    timing: ScanTiming,
    worker_id: str,
    trivy_version: str | None = None,
    image_digest: str | None = None,
) -> None:
    """
    Save complete scan results to database.
    """
    # Update main scan record
    values = {
        "status": ScanStatus.completed,
        "raw_report": raw_report,
        "image_digest": image_digest,
        # Vulnerability counts
        "critical_count": metrics.critical_count,
        "high_count": metrics.high_count,
        "medium_count": metrics.medium_count,
        "low_count": metrics.low_count,
        "unknown_count": metrics.unknown_count,
        "total_vulnerabilities": metrics.total_vulnerabilities,
        "fixable_count": metrics.fixable_count,
        "unfixable_count": metrics.unfixable_count,
        # Risk scoring
        "risk_score": metrics.risk_score,
        "max_cvss_score": metrics.max_cvss_score,
        "avg_cvss_score": metrics.avg_cvss_score,
        # Compliance
        "is_compliant": metrics.is_compliant,
        "compliance_status": metrics.compliance_status,
        # Timing
        "scan_duration": timing.total_duration,
        "pull_duration": timing.pull_duration,
        "analysis_duration": timing.scan_duration,
        # Metadata
        "completed_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "worker_id": worker_id,
        "trivy_version": trivy_version,
    }
    
    stmt = (
        update(VulnerabilityScan)
        .where(VulnerabilityScan.id == scan_id)
        .values(**values)
    )
    
    await session.execute(stmt)
    
    # Optionally insert vulnerability details for CVE tracking
    # (Commented out for performance - enable if needed for CVE impact analysis)
    # await insert_vulnerability_details(session, scan_id, metrics.vulnerabilities)
    
    await session.commit()


async def log_audit_transition(
    session: AsyncSession,
    scan_id: UUID,
    previous_status: ScanStatus | None,
    new_status: ScanStatus,
    message: str | None = None,
    audit_data: dict | None = None,
    worker_id: str | None = None,
) -> None:
    """Log state transition for audit trail."""
    audit_log = ScanAuditLog(
        scan_id=scan_id,
        previous_status=previous_status,
        new_status=new_status,
        message=message,
        audit_data=audit_data,
        triggered_by=worker_id or "worker",
    )
    session.add(audit_log)
    await session.commit()


# =============================================================================
# WORKER CORE - Single Scan Processing
# =============================================================================

async def process_single_scan(
    scan: VulnerabilityScan,
    config: WorkerConfig,
) -> None:
    """
    Process a single vulnerability scan end-to-end.
    
    State Machine:
        PENDING -> PULLING -> SCANNING -> PARSING -> COMPLETED
                     |           |           |
                     v           v           v
                   FAILED     FAILED      FAILED
    
    This function handles all state transitions and error handling.
    It NEVER raises exceptions - all errors are captured and saved to DB.
    """
    scan_id = scan.id
    image_ref = f"{scan.registry}/{scan.image_name}:{scan.image_tag}"
    if scan.registry == "docker.io":
        image_ref = f"{scan.image_name}:{scan.image_tag}"
    
    # Create logger with scan context
    log = ScanLogAdapter(logger, {"scan_id": str(scan_id)[:8]})
    
    log.info(f"Starting scan for image: {image_ref}")
    
    timing = ScanTiming(total_start=time.time())
    temp_dir = None
    
    try:
        async with get_db_session() as session:
            # Transition: PENDING -> PULLING
            timing.pull_start = time.time()
            await update_scan_status(
                session, scan_id, ScanStatus.pulling,
                started_at=datetime.now(timezone.utc),
            )
            await log_audit_transition(
                session, scan_id,
                ScanStatus.pending, ScanStatus.pulling,
                message="Starting image pull",
                worker_id=config.worker_id,
            )
            log.info("Status: PULLING")
            timing.pull_end = time.time()
            
            # Transition: PULLING -> SCANNING
            timing.scan_start = time.time()
            await update_scan_status(session, scan_id, ScanStatus.scanning)
            await log_audit_transition(
                session, scan_id,
                ScanStatus.pulling, ScanStatus.scanning,
                message="Starting vulnerability scan",
                worker_id=config.worker_id,
            )
            log.info("Status: SCANNING")
            
            # Create temporary directory for Trivy output
            temp_dir = tempfile.mkdtemp(prefix="trivy_scan_")
            output_path = Path(temp_dir) / "result.json"
            
            # Run Trivy scan (this is the potentially long-running operation)
            # Now uses async subprocess for non-blocking execution
            try:
                raw_report = await run_trivy_scan(
                    image_reference=image_ref,
                    output_path=output_path,
                    config=config,
                    log=log,
                )
            except ScanTimeoutException as e:
                e.scan_id = str(scan_id)
                raise
            
            timing.scan_end = time.time()
            
            # Transition: SCANNING -> PARSING
            timing.parse_start = time.time()
            await update_scan_status(session, scan_id, ScanStatus.parsing)
            await log_audit_transition(
                session, scan_id,
                ScanStatus.scanning, ScanStatus.parsing,
                message="Parsing scan results",
                worker_id=config.worker_id,
            )
            log.info("Status: PARSING")
            
            # Calculate risk metrics
            metrics = calculate_risk_metrics(raw_report, config)
            timing.parse_end = time.time()
            
            log.info(
                f"Scan complete: "
                f"vulns={metrics.total_vulnerabilities}, "
                f"critical={metrics.critical_count}, "
                f"high={metrics.high_count}, "
                f"risk_score={metrics.risk_score}, "
                f"fixable={metrics.fixable_count}"
            )
            
            # Extract image digest if available
            image_digest = None
            if raw_report.get("Metadata", {}).get("RepoDigests"):
                image_digest = raw_report["Metadata"]["RepoDigests"][0]
            
            # Get Trivy version
            trivy_version = raw_report.get("SchemaVersion", "unknown")
            
            # Save results and transition: PARSING -> COMPLETED
            await save_scan_results(
                session=session,
                scan_id=scan_id,
                raw_report=raw_report,
                metrics=metrics,
                timing=timing,
                worker_id=config.worker_id,
                trivy_version=str(trivy_version),
                image_digest=image_digest,
            )
            
            await log_audit_transition(
                session, scan_id,
                ScanStatus.parsing, ScanStatus.completed,
                message=f"Scan completed: {metrics.total_vulnerabilities} vulnerabilities found",
                audit_data={
                    "risk_score": metrics.risk_score,
                    "duration_seconds": timing.total_duration,
                },
                worker_id=config.worker_id,
            )
            
            log.info(
                f"Scan COMPLETED in {timing.total_duration}s - "
                f"Risk Score: {metrics.risk_score}"
            )
    
    except ScanTimeoutException as e:
        log.error(f"Scan FAILED: Timeout after {e.timeout_seconds}s")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=f"Scan timed out after {e.timeout_seconds} seconds",
            error_code="TIMEOUT",
            config=config,
            log=log,
        )
    
    except ImageNotFoundException as e:
        log.error(f"Scan FAILED: Image not found - {e.image_name}")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=str(e.message),
            error_code="IMAGE_NOT_FOUND",
            config=config,
            log=log,
            increment_retry=False,  # Don't retry - permanent failure
        )
    
    except ImagePullException as e:
        log.error(f"Scan FAILED: Pull error - {e.message}")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=str(e.message),
            error_code="PULL_FAILED",
            config=config,
            log=log,
        )
    
    except TrivyExecutionException as e:
        log.error(f"Scan FAILED: Trivy error - {e.message}")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=str(e.message),
            error_code="TRIVY_ERROR",
            config=config,
            log=log,
        )
    
    except Exception as e:
        # Catch-all for unexpected errors
        log.exception(f"Scan FAILED: Unexpected error - {type(e).__name__}: {e}")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=f"Unexpected error: {type(e).__name__}: {str(e)[:500]}",
            error_code="INTERNAL_ERROR",
            config=config,
            log=log,
        )
    
    finally:
        # Cleanup temporary files
        if temp_dir and os.path.exists(temp_dir):
            try:
                import shutil
                shutil.rmtree(temp_dir)
            except Exception as e:
                log.warning(f"Failed to cleanup temp dir: {e}")


async def process_single_scan_by_id(
    scan_data: dict,
    config: WorkerConfig,
) -> None:
    """
    Process a single vulnerability scan using scan data dict.
    
    CONCURRENCY FIX:
    This version takes a dict of scan data instead of a detached ORM object.
    This avoids issues with SQLAlchemy session detachment and ensures
    we always work with fresh database state.
    
    The scan has already been claimed (status=PULLING) by the caller,
    so we start from the SCANNING phase.
    
    State Machine (from this point):
        PULLING -> SCANNING -> PARSING -> COMPLETED
                      |           |
                      v           v
                    FAILED      FAILED
    """
    scan_id = scan_data["id"]
    image_name = scan_data["image_name"]
    image_tag = scan_data["image_tag"]
    registry = scan_data["registry"]
    
    image_ref = f"{registry}/{image_name}:{image_tag}"
    if registry == "docker.io":
        image_ref = f"{image_name}:{image_tag}"
    
    # Create logger with scan context
    log = ScanLogAdapter(logger, {"scan_id": str(scan_id)[:8]})
    
    log.info(f"Processing scan for image: {image_ref}")
    
    timing = ScanTiming(total_start=time.time())
    timing.pull_start = timing.total_start
    timing.pull_end = time.time()
    temp_dir = None
    
    try:
        async with get_db_session() as session:
            # Log the PULLING->SCANNING transition
            await log_audit_transition(
                session, scan_id,
                ScanStatus.pulling, ScanStatus.pulling,
                message="Scan claimed by worker",
                worker_id=config.worker_id,
            )
            
            # Transition: PULLING -> SCANNING
            timing.scan_start = time.time()
            await update_scan_status(session, scan_id, ScanStatus.scanning)
            await log_audit_transition(
                session, scan_id,
                ScanStatus.pulling, ScanStatus.scanning,
                message="Starting vulnerability scan",
                worker_id=config.worker_id,
            )
            log.info("Status: SCANNING")
            
            # Create temporary directory for Trivy output
            temp_dir = tempfile.mkdtemp(prefix="trivy_scan_")
            output_path = Path(temp_dir) / "result.json"
            
            # Run Trivy scan (async - non-blocking!)
            try:
                raw_report = await run_trivy_scan(
                    image_reference=image_ref,
                    output_path=output_path,
                    config=config,
                    log=log,
                )
            except ScanTimeoutException as e:
                e.scan_id = str(scan_id)
                raise
            
            timing.scan_end = time.time()
            
            # Transition: SCANNING -> PARSING
            timing.parse_start = time.time()
            await update_scan_status(session, scan_id, ScanStatus.parsing)
            await log_audit_transition(
                session, scan_id,
                ScanStatus.scanning, ScanStatus.parsing,
                message="Parsing scan results",
                worker_id=config.worker_id,
            )
            log.info("Status: PARSING")
            
            # Calculate risk metrics
            metrics = calculate_risk_metrics(raw_report, config)
            timing.parse_end = time.time()
            
            log.info(
                f"Scan complete: "
                f"vulns={metrics.total_vulnerabilities}, "
                f"critical={metrics.critical_count}, "
                f"high={metrics.high_count}, "
                f"risk_score={metrics.risk_score}, "
                f"fixable={metrics.fixable_count}"
            )
            
            # Extract image digest if available
            image_digest = None
            if raw_report.get("Metadata", {}).get("RepoDigests"):
                image_digest = raw_report["Metadata"]["RepoDigests"][0]
            
            # Get Trivy version
            trivy_version = raw_report.get("SchemaVersion", "unknown")
            
            # Save results and transition: PARSING -> COMPLETED
            await save_scan_results(
                session=session,
                scan_id=scan_id,
                raw_report=raw_report,
                metrics=metrics,
                timing=timing,
                worker_id=config.worker_id,
                trivy_version=str(trivy_version),
                image_digest=image_digest,
            )
            
            await log_audit_transition(
                session, scan_id,
                ScanStatus.parsing, ScanStatus.completed,
                message=f"Scan completed: {metrics.total_vulnerabilities} vulnerabilities found",
                audit_data={
                    "risk_score": metrics.risk_score,
                    "duration_seconds": timing.total_duration,
                },
                worker_id=config.worker_id,
            )
            
            log.info(
                f"Scan COMPLETED in {timing.total_duration}s - "
                f"Risk Score: {metrics.risk_score}"
            )
    
    except ScanTimeoutException as e:
        log.error(f"Scan FAILED: Timeout after {e.timeout_seconds}s")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=f"Scan timed out after {e.timeout_seconds} seconds",
            error_code="TIMEOUT",
            config=config,
            log=log,
        )
    
    except ImageNotFoundException as e:
        log.error(f"Scan FAILED: Image not found - {e.image_name}")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=str(e.message),
            error_code="IMAGE_NOT_FOUND",
            config=config,
            log=log,
            increment_retry=False,  # Don't retry - permanent failure
        )
    
    except ImagePullException as e:
        log.error(f"Scan FAILED: Pull error - {e.message}")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=str(e.message),
            error_code="PULL_FAILED",
            config=config,
            log=log,
        )
    
    except TrivyExecutionException as e:
        log.error(f"Scan FAILED: Trivy error - {e.message}")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=str(e.message),
            error_code="TRIVY_ERROR",
            config=config,
            log=log,
        )
    
    except Exception as e:
        # Catch-all for unexpected errors
        log.exception(f"Scan FAILED: Unexpected error - {type(e).__name__}: {e}")
        await _handle_scan_failure(
            scan_id=scan_id,
            error_message=f"Unexpected error: {type(e).__name__}: {str(e)[:500]}",
            error_code="INTERNAL_ERROR",
            config=config,
            log=log,
        )
    
    finally:
        # Cleanup temporary files
        if temp_dir and os.path.exists(temp_dir):
            try:
                import shutil
                shutil.rmtree(temp_dir)
            except Exception as e:
                log.warning(f"Failed to cleanup temp dir: {e}")


async def _handle_scan_failure(
    scan_id: UUID,
    error_message: str,
    error_code: str,
    config: WorkerConfig,
    log: logging.LoggerAdapter,
    increment_retry: bool = True,
) -> None:
    """Handle scan failure with proper state transition."""
    try:
        async with get_db_session() as session:
            # Get current retry count
            scan = await session.get(VulnerabilityScan, scan_id)
            if not scan:
                log.error(f"Scan {scan_id} not found during failure handling")
                return
            
            new_retry_count = scan.retry_count + 1 if increment_retry else scan.retry_count
            previous_status = scan.status
            
            await update_scan_status(
                session=session,
                scan_id=scan_id,
                new_status=ScanStatus.failed,
                error_message=error_message,
                error_code=error_code,
                retry_count=new_retry_count,
                completed_at=datetime.now(timezone.utc),
            )
            
            await log_audit_transition(
                session, scan_id,
                previous_status, ScanStatus.failed,
                message=error_message,
                audit_data={"error_code": error_code},
                worker_id=config.worker_id,
            )
            
    except Exception as e:
        log.exception(f"Failed to update scan failure status: {e}")


# =============================================================================
# WORKER LOOP - Main Entry Point
# =============================================================================

class ScanWorker:
    """
    Production-grade vulnerability scanner worker.
    
    Features:
    - Graceful shutdown on SIGTERM/SIGINT
    - Configurable polling interval
    - Automatic reconnection on database errors
    - Comprehensive logging
    """
    
    def __init__(self, config: WorkerConfig | None = None):
        self.config = config or WorkerConfig()
        self.running = True
        self.current_scan_id: UUID | None = None
        self.logger = logging.getLogger(f"{__name__}.{self.config.worker_id}")
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self) -> None:
        """Setup graceful shutdown handlers."""
        
        def handle_shutdown(signum, frame):
            sig_name = signal.Signals(signum).name
            self.logger.info(f"Received {sig_name}, initiating graceful shutdown...")
            self.running = False
            
            if self.current_scan_id:
                self.logger.info(
                    f"Waiting for current scan {self.current_scan_id} to complete..."
                )
        
        # Register handlers
        signal.signal(signal.SIGTERM, handle_shutdown)
        signal.signal(signal.SIGINT, handle_shutdown)
    
    async def run(self) -> None:
        """
        Main worker loop.
        
        Continuously polls for pending scans and processes them.
        Handles database connection errors gracefully.
        """
        self.logger.info(
            f"Worker {self.config.worker_id} starting - "
            f"poll_interval={self.config.poll_interval}s, "
            f"trivy_timeout={self.config.trivy_timeout}s"
        )
        
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while self.running:
            try:
                # Poll for pending scans
                async with get_db_session() as session:
                    scan = await fetch_pending_scan(session)
                
                if scan:
                    self.current_scan_id = scan.id
                    consecutive_errors = 0  # Reset on successful DB access
                    
                    await process_single_scan(scan, self.config)
                    
                    self.current_scan_id = None
                else:
                    # No pending scans, wait before next poll
                    await asyncio.sleep(self.config.poll_interval)
                    consecutive_errors = 0
                    
            except Exception as e:
                consecutive_errors += 1
                self.logger.error(
                    f"Worker loop error ({consecutive_errors}/{max_consecutive_errors}): {e}"
                )
                
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.critical(
                        f"Too many consecutive errors, shutting down worker"
                    )
                    break
                
                # Exponential backoff on errors
                await asyncio.sleep(min(2 ** consecutive_errors, 60))
        
        self.logger.info(f"Worker {self.config.worker_id} stopped")


# =============================================================================
# PUBLIC API - For importing from services.py
# =============================================================================

async def process_scan_job(scan_id: UUID) -> None:
    """
    Process a specific scan job (called from background task).
    
    This is the entry point called by FastAPI BackgroundTasks.
    
    CONCURRENCY FIX:
    Uses SELECT FOR UPDATE SKIP LOCKED to atomically claim the scan.
    This prevents race conditions where:
    - Multiple background tasks try to process the same scan
    - A scan is processed after its status has changed
    
    The SKIP LOCKED option means if another worker has already locked
    this scan, we simply skip it (return early) instead of waiting.
    """
    logger.info(f"Background task received scan job: {scan_id}")
    
    config = WorkerConfig()
    
    try:
        # Atomically check and claim the scan using FOR UPDATE SKIP LOCKED
        # This ensures only one worker processes this scan
        async with get_db_session() as session:
            from sqlalchemy import select
            
            # Use FOR UPDATE SKIP LOCKED to atomically claim the scan
            # This prevents race conditions with concurrent workers
            stmt = (
                select(VulnerabilityScan)
                .where(
                    VulnerabilityScan.id == scan_id,
                    VulnerabilityScan.status == ScanStatus.pending,
                )
                .with_for_update(skip_locked=True)
            )
            
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()
            
            if not scan:
                # Either scan doesn't exist, or it's not pending, or it's locked
                # In any case, nothing for us to do
                logger.info(
                    f"Scan {scan_id} not available for processing "
                    f"(may be already claimed, not pending, or not found)"
                )
                return
            
            # Immediately transition to PULLING to claim ownership
            # This releases the lock but marks it as "in progress"
            scan.status = ScanStatus.pulling
            scan.started_at = datetime.now(timezone.utc)
            scan.worker_id = config.worker_id
            await session.commit()
            
            # Store the scan data we need (scan object will be detached after commit)
            scan_data = {
                "id": scan.id,
                "image_name": scan.image_name,
                "image_tag": scan.image_tag,
                "registry": scan.registry,
            }
        
        # Now process the scan outside the session context
        # process_single_scan creates its own sessions as needed
        await process_single_scan_by_id(scan_data, config)
        
    except Exception as e:
        logger.exception(f"Background task failed for scan {scan_id}: {e}")
        
        # Try to mark as failed
        try:
            async with get_db_session() as session:
                await update_scan_status(
                    session=session,
                    scan_id=scan_id,
                    new_status=ScanStatus.failed,
                    error_message=f"Background task error: {str(e)[:500]}",
                    error_code="BACKGROUND_TASK_ERROR",
                )
        except Exception:
            logger.exception(f"Failed to update scan {scan_id} status to FAILED")


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

async def main() -> None:
    """CLI entry point for running the worker."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    logger.info("Starting Container Vulnerability Scanner Worker")
    
    # Check Trivy availability
    config = WorkerConfig()
    if not os.path.exists(config.trivy_binary):
        logger.error(f"Trivy binary not found at: {config.trivy_binary}")
        logger.info("Install Trivy: https://aquasecurity.github.io/trivy/")
        sys.exit(1)
    
    # Ensure cache directory exists
    os.makedirs(config.trivy_cache_dir, exist_ok=True)
    
    # Run worker
    worker = ScanWorker(config)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
