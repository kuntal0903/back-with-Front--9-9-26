"""
tests/integration/test_production_readiness.py

Phase 17 — Production Readiness Verification Suite.
Validates environment configuration separation, JSON logging formatting,
health & readiness probes, internal exception redaction (no secret/stack trace leaks),
and Docker container readiness.
"""

import os
import json
import pytest
from httpx import AsyncClient, ASGITransport

from app.core.config import settings, Settings
from app.core.logging import JsonFormatter
from app.main import app
from app.services.target.processor import TargetProcessor


@pytest.mark.asyncio
async def test_production_configuration_environment_separation() -> None:
    """Verify configuration loads externalized environment settings cleanly."""
    dev_settings = Settings(app_env="development")
    assert dev_settings.is_development is True
    assert dev_settings.is_production is False
    assert dev_settings.is_test is False

    prod_settings = Settings(app_env="production")
    assert prod_settings.is_production is True
    assert prod_settings.is_development is False

    test_settings = Settings(app_env="test")
    assert test_settings.is_test is True


@pytest.mark.asyncio
async def test_production_health_endpoint_metrics() -> None:
    """Verify GET /api/v1/health returns HTTP 200 with readiness metrics."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["db_status"] == "healthy"
    assert "storage" in data
    assert "assets" in data["storage"]
    assert "scans" in data["storage"]


def test_json_logging_configuration() -> None:
    """Verify production JsonFormatter outputs structured JSON strings."""
    import logging
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Production log test",
        args=(),
        exc_info=None,
    )
    record.scan_id = "scan-prod-123"
    record.tool = "dns_scan"

    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test_logger"
    assert parsed["message"] == "Production log test"
    assert parsed["scan_id"] == "scan-prod-123"
    assert parsed["tool"] == "dns_scan"
    assert "timestamp" in parsed


@pytest.mark.asyncio
async def test_internal_error_redaction_and_no_secret_exposure(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify unhandled 500 exceptions produce generic error responses
    without exposing raw stack traces or internal implementation secrets to callers.
    """
    def mock_crashing_process(self, raw_target: str):
        raise RuntimeError("Secret DB password or internal traceback")

    # Monkeypatch TargetProcessor.process to raise unexpected internal error
    monkeypatch.setattr(TargetProcessor, "process", mock_crashing_process)

    # Use raise_app_exceptions=False so ASGITransport lets exception handler produce HTTP 500 response
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"target": "example.com", "mode": "full"}
        response = await client.post("/api/v1/scans", json=payload)

    assert response.status_code == 500
    data = response.json()
    assert data["status"] == "failed"
    assert data["error_type"] == "internal_error"
    assert data["message"] == "An unexpected internal error occurred."
    assert "Secret DB password" not in response.text
    assert "traceback" not in response.text.lower()


def test_dockerfile_and_deployment_files_exist() -> None:
    """Verify Dockerfile and docker-compose configurations are present and valid."""
    assert os.path.exists("Dockerfile"), "Dockerfile missing"
    assert os.path.exists("docker-compose.yml"), "docker-compose.yml missing"
    
    with open("Dockerfile", "r", encoding="utf-8") as f:
        dockerfile_content = f.read()

    assert "python:3.12-slim" in dockerfile_content
    assert "HEALTHCHECK" in dockerfile_content
    assert "useradd" in dockerfile_content
