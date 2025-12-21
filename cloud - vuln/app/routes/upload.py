"""
Upload endpoint for Docker image tarballs and Dockerfiles
"""

import os
import uuid
import shutil
import tempfile
import asyncio
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from app.database import get_db_session
from app.models import VulnerabilityScan, ScanStatus
from app.worker import process_scan_job

router = APIRouter()

# Max file sizes
MAX_TARBALL_SIZE = 2 * 1024 * 1024 * 1024  # 2GB
MAX_DOCKERFILE_SIZE = 1 * 1024 * 1024  # 1MB

# Upload directory
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/tmp/vulnscan_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/scan/upload")
async def upload_and_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    type: str = Form("tarball"),  # 'tarball' or 'dockerfile'
):
    """
    Upload a Docker image tarball or Dockerfile for scanning.
    
    - **tarball**: A .tar or .tar.gz file created with `docker save`
    - **dockerfile**: A Dockerfile to build and scan
    """
    
    # Validate file type
    filename = file.filename.lower() if file.filename else ""
    
    if type == "tarball":
        if not any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz']):
            raise HTTPException(
                status_code=400, 
                detail="Invalid file type. Expected .tar, .tar.gz, or .tgz"
            )
        max_size = MAX_TARBALL_SIZE
    elif type == "dockerfile":
        if not (filename == "dockerfile" or filename.endswith(".dockerfile")):
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Expected Dockerfile or .dockerfile"
            )
        max_size = MAX_DOCKERFILE_SIZE
    else:
        raise HTTPException(status_code=400, detail="Invalid upload type")
    
    # Create unique upload directory
    upload_id = str(uuid.uuid4())
    upload_path = UPLOAD_DIR / upload_id
    upload_path.mkdir(parents=True, exist_ok=True)
    
    try:
        # Save uploaded file
        file_path = upload_path / (file.filename or f"upload.{type}")
        
        # Stream file to disk with size check
        total_size = 0
        with open(file_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):  # 1MB chunks
                total_size += len(chunk)
                if total_size > max_size:
                    # Clean up and raise error
                    shutil.rmtree(upload_path, ignore_errors=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Maximum size: {max_size // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        # Generate image name from upload
        if type == "tarball":
            image_name = f"upload-{upload_id[:8]}"
            image_tag = "latest"
        else:
            image_name = f"dockerfile-{upload_id[:8]}"
            image_tag = "build"
        
        # Create scan record
        async with get_db_session() as session:
            scan = VulnerabilityScan(
                image_name=image_name,
                image_tag=image_tag,
                registry="local",
                status=ScanStatus.pending,
            )
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
            scan_id = scan.id
        
        # Queue background scan
        background_tasks.add_task(
            process_uploaded_scan,
            scan_id=str(scan_id),
            upload_path=str(upload_path),
            file_path=str(file_path),
            upload_type=type,
        )
        
        return JSONResponse(
            status_code=202,
            content={
                "id": str(scan_id),
                "image_name": image_name,
                "image_tag": image_tag,
                "status": "pending",
                "message": f"Upload received. Scan queued.",
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Clean up on error
        shutil.rmtree(upload_path, ignore_errors=True)
        raise HTTPException(status_code=500, detail=str(e))


async def process_uploaded_scan(
    scan_id: str,
    upload_path: str,
    file_path: str,
    upload_type: str,
):
    """Background task to process uploaded image scan."""
    import subprocess
    import json
    from datetime import datetime, timezone
    
    upload_path = Path(upload_path)
    file_path = Path(file_path)
    
    try:
        async with get_db_session() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id)
            )
            scan = result.scalar_one_or_none()
            if not scan:
                return
            
            scan.status = ScanStatus.scanning
            scan.started_at = datetime.now(timezone.utc)
            await session.commit()
        
        # Run Trivy scan
        trivy_binary = os.getenv("TRIVY_BINARY_PATH", "/usr/bin/trivy")
        trivy_cache = os.getenv("TRIVY_CACHE_DIR", "/app/trivy-cache")
        trivy_timeout = os.getenv("TRIVY_TIMEOUT_SECONDS", "300")
        
        output_file = upload_path / "trivy_result.json"
        
        if upload_type == "tarball":
            # Scan tarball directly
            cmd = [
                trivy_binary, "image",
                "--input", str(file_path),
                "--format", "json",
                "--output", str(output_file),
                "--timeout", f"{trivy_timeout}s",
                "--scanners", "vuln",
                "--cache-dir", trivy_cache,
            ]
        else:
            # For Dockerfile, we'd need to build first (simplified - just scan as config)
            cmd = [
                trivy_binary, "config",
                str(file_path),
                "--format", "json",
                "--output", str(output_file),
                "--timeout", f"{trivy_timeout}s",
            ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await process.communicate()
        
        # Parse results
        async with get_db_session() as session:
            result = await session.execute(
                select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id)
            )
            scan = result.scalar_one_or_none()
            if not scan:
                return
            
            if output_file.exists():
                with open(output_file) as f:
                    raw_report = json.load(f)
                
                scan.raw_report = raw_report
                scan.status = ScanStatus.parsing
                await session.commit()
                
                # Parse vulnerabilities
                critical = high = medium = low = unknown = 0
                fixable = unfixable = 0
                max_cvss = 0.0
                cvss_scores = []
                
                for result_item in raw_report.get("Results", []):
                    for vuln in result_item.get("Vulnerabilities", []):
                        severity = vuln.get("Severity", "UNKNOWN").upper()
                        if severity == "CRITICAL":
                            critical += 1
                        elif severity == "HIGH":
                            high += 1
                        elif severity == "MEDIUM":
                            medium += 1
                        elif severity == "LOW":
                            low += 1
                        else:
                            unknown += 1
                        
                        if vuln.get("FixedVersion"):
                            fixable += 1
                        else:
                            unfixable += 1
                        
                        # CVSS scores
                        cvss = vuln.get("CVSS", {})
                        for source in cvss.values():
                            if "V3Score" in source:
                                score = source["V3Score"]
                                cvss_scores.append(score)
                                max_cvss = max(max_cvss, score)
                
                # Update scan record
                scan.critical_count = critical
                scan.high_count = high
                scan.medium_count = medium
                scan.low_count = low
                scan.unknown_count = unknown
                scan.total_vulnerabilities = critical + high + medium + low + unknown
                scan.fixable_count = fixable
                scan.unfixable_count = unfixable
                scan.risk_score = (critical * 100) + (high * 50) + (medium * 10) + (low * 1)
                scan.max_cvss_score = max_cvss if max_cvss > 0 else None
                scan.avg_cvss_score = sum(cvss_scores) / len(cvss_scores) if cvss_scores else None
                scan.is_compliant = critical == 0 and high == 0
                scan.status = ScanStatus.completed
                scan.completed_at = datetime.now(timezone.utc)
                scan.scan_duration = (scan.completed_at - scan.started_at).total_seconds()
                
                await session.commit()
            else:
                scan.status = ScanStatus.failed
                scan.error_message = stderr.decode() if stderr else "Scan failed - no output"
                await session.commit()
                
    except Exception as e:
        async with get_db_session() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id)
            )
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.failed
                scan.error_message = str(e)
                await session.commit()
    
    finally:
        # Clean up upload directory
        shutil.rmtree(upload_path, ignore_errors=True)
