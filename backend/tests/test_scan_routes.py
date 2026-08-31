"""
tests/test_scan_routes.py

Integration tests for scan routes (POST /api/v1/scans, GET endpoints).
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.core.config import settings
from app.core.constants import ERROR_INVALID_INPUT, ERROR_INVALID_TARGET, ERROR_SCOPE_REJECTED
from app.main import app


@pytest.mark.asyncio
async def test_create_scan_success() -> None:
    """POST /scans should succeed and return ScanCreatedResponse for valid target."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {"target": "example.com", "mode": "full"}
        response = await client.post("/api/v1/scans", json=payload)
    
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "queued"
    assert "scan_id" in data
    assert "created_at" in data
    assert data["target"]["original"] == "example.com"
    assert data["target"]["normalized"] == "example.com"
    assert data["target"]["target_type"] == "domain"


@pytest.mark.asyncio
async def test_create_scan_invalid_input() -> None:
    """POST /scans should fail with HTTP 400 and structured error on whitespace target."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {"target": "   ", "mode": "full"}
        response = await client.post("/api/v1/scans", json=payload)
        
    assert response.status_code == 400
    data = response.json()
    assert data["status"] == "failed"
    assert data["error_type"] == ERROR_INVALID_INPUT
    assert "message" in data


@pytest.mark.asyncio
async def test_create_scan_invalid_target() -> None:
    """POST /scans should fail with HTTP 400 and structured error on invalid target."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {"target": "example.123", "mode": "full"}
        response = await client.post("/api/v1/scans", json=payload)
        
    assert response.status_code == 400
    data = response.json()
    assert data["status"] == "failed"
    assert data["error_type"] == ERROR_INVALID_TARGET


@pytest.mark.asyncio
async def test_create_scan_scope_rejection() -> None:
    """POST /scans should fail with HTTP 400 and structured error on loopback IP when blocked."""
    # Force settings app_env to production to block private/loopback IPs in scope checker
    original_env = settings.app_env
    settings.app_env = "production"
    
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            payload = {"target": "127.0.0.1", "mode": "full"}
            response = await client.post("/api/v1/scans", json=payload)
            
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "failed"
        assert data["error_type"] == ERROR_SCOPE_REJECTED
    finally:
        settings.app_env = original_env


@pytest.mark.asyncio
async def test_create_scan_requires_scans_field() -> None:
    """POST /scans should fail with HTTP 422 if scans is empty in individual/selected mode."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {"target": "example.com", "mode": "individual", "scans": []}
        response = await client.post("/api/v1/scans", json=payload)
        
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_scan_rejects_unknown_scans() -> None:
    """POST /scans should fail with HTTP 422 if scans contains unknown tool IDs."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {"target": "example.com", "mode": "selected", "scans": ["nonexistent_scanner"]}
        response = await client.post("/api/v1/scans", json=payload)
        
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_scan_status_success() -> None:
    """GET /scans/{scan_id} should return 200 and scan details if scan exists."""
    from app.orchestrator.db import scan_db
    from app.models.scan import Scan
    from app.schemas.scan_request import TargetInfo
    
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(scan_id="some-test-scan-id", target=target_info, status="running", mode="full", progress=50)
    scan_db.save_scan(scan)
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/scans/some-test-scan-id")
        
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "some-test-scan-id"
    assert data["status"] == "running"
    assert data["progress"] == 50


@pytest.mark.asyncio
async def test_get_scan_status_not_found() -> None:
    """GET /scans/{scan_id} should return 404 if scan does not exist."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/scans/nonexistent-id")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_scan_results_success() -> None:
    """GET /scans/{scan_id}/results should return 200 and results if scan result is available."""
    from app.orchestrator.db import scan_db
    from app.models.scan import Scan
    from app.models.results import ScanResult
    from app.schemas.scan_request import TargetInfo
    
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(scan_id="test-results-id", target=target_info, status="completed", mode="full", progress=100)
    scan_db.save_scan(scan)
    
    res = ScanResult(scan_id="test-results-id", target=target_info, assets=[], relationships=[], evidence=[], errors=[])
    scan_db.save_result(res)
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/scans/test-results-id/results")
        
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "test-results-id"
    assert isinstance(data["assets"], list)


@pytest.mark.asyncio
async def test_get_scan_results_running() -> None:
    """GET /scans/{scan_id}/results should return 202 if scan is still in progress."""
    from app.orchestrator.db import scan_db
    from app.models.scan import Scan
    from app.schemas.scan_request import TargetInfo
    
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(scan_id="test-running-id", target=target_info, status="running", mode="full", progress=40)
    scan_db.save_scan(scan)
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/scans/test-running-id/results")
        
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "running"
    assert "still in progress" in data["message"]

