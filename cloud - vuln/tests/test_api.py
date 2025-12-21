"""
API Integration Tests
=====================
Tests for the FastAPI endpoints with idempotency logic.
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool

from app.main import app, get_scan_service
from app.database import Base, get_db
from app.models import VulnerabilityScan, ScanStatus
from app.services import ScanService


# =============================================================================
# TEST DATABASE SETUP
# =============================================================================

# Use SQLite for tests (in-memory)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    poolclass=NullPool,
    echo=False,
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def override_get_db():
    """Override database dependency for tests."""
    async with TestSessionLocal() as session:
        yield session


async def override_get_scan_service():
    """Override service dependency for tests."""
    async with TestSessionLocal() as session:
        yield ScanService(session)


# Apply overrides
app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_scan_service] = override_get_scan_service


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(autouse=True)
async def setup_database():
    """Create tables before each test, drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client():
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def db_session():
    """Direct database session for test setup."""
    async with TestSessionLocal() as session:
        yield session


# =============================================================================
# HEALTH CHECK TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Test basic health endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


@pytest.mark.asyncio
async def test_liveness_check(client: AsyncClient):
    """Test Kubernetes liveness probe endpoint."""
    response = await client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


# =============================================================================
# SCAN SUBMISSION TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_submit_scan_new_image(client: AsyncClient):
    """Test submitting a scan for a new image."""
    response = await client.post(
        "/api/v1/scan",
        json={
            "image_name": "nginx",
            "image_tag": "latest",
            "registry": "docker.io",
            "force_rescan": False,
        },
    )
    
    # Should return 202 Accepted for new scan
    assert response.status_code == 202
    data = response.json()
    
    assert "id" in data
    assert data["full_image"] == "nginx:latest"
    assert data["cache_hit"] is False
    assert data["status"] == "pending"
    assert data["message"] == "Scan queued successfully"
    
    # Verify X-Cache header
    assert response.headers.get("X-Cache") == "MISS"


@pytest.mark.asyncio
async def test_submit_scan_idempotency_cache_miss(client: AsyncClient):
    """Test that duplicate requests within TTL return cached result."""
    # First request - creates new scan
    response1 = await client.post(
        "/api/v1/scan",
        json={"image_name": "python", "image_tag": "3.11"},
    )
    assert response1.status_code == 202
    scan_id_1 = response1.json()["id"]
    
    # Second request - should NOT be a cache hit because first scan is still PENDING
    # (idempotency only returns cached COMPLETED scans)
    response2 = await client.post(
        "/api/v1/scan",
        json={"image_name": "python", "image_tag": "3.11"},
    )
    
    # Since first scan is still PENDING (not COMPLETED), we get the in-progress scan
    assert response2.status_code == 202
    data2 = response2.json()
    
    # Should return the same scan ID (in-progress detection)
    assert data2["id"] == scan_id_1
    assert data2["cache_hit"] is False


@pytest.mark.asyncio
async def test_submit_scan_idempotency_cache_hit(client: AsyncClient, db_session: AsyncSession):
    """Test that completed scans return cached result."""
    # Pre-create a COMPLETED scan in the database
    existing_scan = VulnerabilityScan(
        image_name="redis",
        image_tag="7.0",
        registry="docker.io",
        status=ScanStatus.completed,
        risk_score=50,
        critical_count=0,
        high_count=1,
        is_compliant=False,
    )
    db_session.add(existing_scan)
    await db_session.commit()
    await db_session.refresh(existing_scan)
    
    # Request scan for same image - should return cached
    response = await client.post(
        "/api/v1/scan",
        json={"image_name": "redis", "image_tag": "7.0"},
    )
    
    assert response.status_code == 200  # 200 for cache hit
    data = response.json()
    
    assert data["cache_hit"] is True
    assert data["id"] == str(existing_scan.id)
    assert data["message"] == "Returning cached scan result"
    
    # Verify X-Cache header indicates HIT
    assert response.headers.get("X-Cache") == "HIT"


@pytest.mark.asyncio
async def test_submit_scan_force_rescan(client: AsyncClient, db_session: AsyncSession):
    """Test that force_rescan bypasses cache."""
    # Pre-create a COMPLETED scan
    existing_scan = VulnerabilityScan(
        image_name="alpine",
        image_tag="3.18",
        registry="docker.io",
        status=ScanStatus.completed,
    )
    db_session.add(existing_scan)
    await db_session.commit()
    await db_session.refresh(existing_scan)
    
    # Request with force_rescan=True
    response = await client.post(
        "/api/v1/scan",
        json={
            "image_name": "alpine",
            "image_tag": "3.18",
            "force_rescan": True,
        },
    )
    
    assert response.status_code == 202  # New scan created
    data = response.json()
    
    assert data["cache_hit"] is False
    assert data["id"] != str(existing_scan.id)  # Different scan ID
    
    # Verify X-Cache header indicates BYPASS (force_rescan=True)
    assert response.headers.get("X-Cache") == "BYPASS"


@pytest.mark.asyncio
async def test_submit_scan_validation_error(client: AsyncClient):
    """Test validation error for invalid image name."""
    response = await client.post(
        "/api/v1/scan",
        json={"image_name": "INVALID--IMAGE"},  # Invalid format
    )
    
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"


# =============================================================================
# SCAN RETRIEVAL TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_get_scan_by_id(client: AsyncClient, db_session: AsyncSession):
    """Test retrieving a scan by ID."""
    # Create a scan
    scan = VulnerabilityScan(
        image_name="ubuntu",
        image_tag="22.04",
        registry="docker.io",
        status=ScanStatus.completed,
        risk_score=150,
        critical_count=1,
        high_count=2,
        medium_count=5,
        total_vulnerabilities=8,
        is_compliant=False,
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    
    # Retrieve it
    response = await client.get(f"/api/v1/scan/{scan.id}")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["id"] == str(scan.id)
    assert data["image_name"] == "ubuntu"
    assert data["vulnerability_counts"]["critical"] == 1
    assert data["risk_assessment"]["risk_score"] == 150
    assert data["risk_assessment"]["is_compliant"] is False


@pytest.mark.asyncio
async def test_get_scan_not_found(client: AsyncClient):
    """Test 404 for non-existent scan."""
    fake_id = uuid4()
    response = await client.get(f"/api/v1/scan/{fake_id}")
    
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "SCAN_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_scan_status(client: AsyncClient, db_session: AsyncSession):
    """Test lightweight status endpoint."""
    scan = VulnerabilityScan(
        image_name="postgres",
        image_tag="15",
        registry="docker.io",
        status=ScanStatus.scanning,
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    
    response = await client.get(f"/api/v1/scan/{scan.id}/status")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "scanning"
    assert data["progress"] == 50
    assert data["is_terminal"] is False


# =============================================================================
# LIST SCANS TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_list_scans_empty(client: AsyncClient):
    """Test listing scans when database is empty."""
    response = await client.get("/api/v1/scans")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["items"] == []
    assert data["pagination"]["total"] == 0


@pytest.mark.asyncio
async def test_list_scans_with_data(client: AsyncClient, db_session: AsyncSession):
    """Test listing scans with pagination."""
    # Create multiple scans
    for i in range(5):
        scan = VulnerabilityScan(
            image_name=f"image{i}",
            image_tag="latest",
            registry="docker.io",
            status=ScanStatus.completed,
            risk_score=i * 10,
        )
        db_session.add(scan)
    await db_session.commit()
    
    response = await client.get("/api/v1/scans?page=1&page_size=3")
    
    assert response.status_code == 200
    data = response.json()
    
    assert len(data["items"]) == 3
    assert data["pagination"]["total"] == 5
    assert data["pagination"]["has_next"] is True


# =============================================================================
# DASHBOARD TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_dashboard_stats(client: AsyncClient, db_session: AsyncSession):
    """Test dashboard statistics endpoint."""
    # Create some scans with different statuses
    scans = [
        VulnerabilityScan(
            image_name="app1", image_tag="v1", registry="docker.io",
            status=ScanStatus.completed, is_compliant=True, risk_score=0,
        ),
        VulnerabilityScan(
            image_name="app2", image_tag="v1", registry="docker.io",
            status=ScanStatus.completed, is_compliant=False, risk_score=150,
            critical_count=1,
        ),
        VulnerabilityScan(
            image_name="app3", image_tag="v1", registry="docker.io",
            status=ScanStatus.failed,
        ),
        VulnerabilityScan(
            image_name="app4", image_tag="v1", registry="docker.io",
            status=ScanStatus.pending,
        ),
    ]
    for scan in scans:
        db_session.add(scan)
    await db_session.commit()
    
    response = await client.get("/api/v1/dashboard/stats")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["total_scans"] == 4
    assert data["completed_scans"] == 2
    assert data["failed_scans"] == 1
    assert data["pending_scans"] == 1
    assert data["compliant_images"] == 1
    assert data["non_compliant_images"] == 1


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_request_id_header(client: AsyncClient):
    """Test that request ID is returned in response headers."""
    response = await client.get("/health")
    
    assert "X-Request-ID" in response.headers


@pytest.mark.asyncio
async def test_custom_request_id(client: AsyncClient):
    """Test that custom request ID is preserved."""
    custom_id = "my-custom-request-id"
    response = await client.get(
        "/health",
        headers={"X-Request-ID": custom_id},
    )
    
    assert response.headers["X-Request-ID"] == custom_id
