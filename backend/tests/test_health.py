"""
tests/test_health.py

Tests for the /api/v1/health endpoint.

These tests verify:
  1. The health endpoint responds with HTTP 200
  2. The response body is structured correctly
  3. Required fields are present
  4. The status field equals "healthy"
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.mark.asyncio
async def test_health_endpoint_returns_200() -> None:
    """Health endpoint must respond with HTTP 200."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_health_endpoint_returns_healthy_status() -> None:
    """Health endpoint must return status='healthy'."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_endpoint_response_structure() -> None:
    """Health endpoint response must contain status, version, and environment fields."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "environment" in data


@pytest.mark.asyncio
async def test_health_endpoint_version_is_string() -> None:
    """The version field must be a non-empty string."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
    data = response.json()
    assert isinstance(data["version"], str)
    assert len(data["version"]) > 0


@pytest.mark.asyncio
async def test_health_endpoint_environment_is_string() -> None:
    """The environment field must be a non-empty string."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
    data = response.json()
    assert isinstance(data["environment"], str)
    assert len(data["environment"]) > 0
