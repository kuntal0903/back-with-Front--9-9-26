"""
app/api/routes/health.py

Production-ready Health and Readiness check endpoint.

GET /api/v1/health

Returns structured readiness metrics for container probes (Docker/Kubernetes).
"""

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.constants import PROJECT_VERSION
from app.orchestrator.db import scan_db
from app.services.assets.db import asset_db

router = APIRouter()


class HealthResponse(BaseModel):
    """Structured response for the production health check endpoint."""

    status: str = Field(description="Overall system readiness status: healthy | degraded | unhealthy")
    version: str = Field(description="Project release version")
    environment: str = Field(description="Runtime environment name")
    db_status: str = Field(description="In-memory state database status")
    storage: dict[str, int] = Field(description="Current in-memory asset and scan record counts")


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health & Readiness Check",
    description="Returns current system readiness and internal component statuses for load balancer health probes.",
    tags=["System"],
)
async def health_check() -> HealthResponse:
    """
    Health & Readiness probe endpoint.
    """
    # Evaluate internal database availability
    assets_count = len(asset_db.get_assets())
    scans_count = len(scan_db._scans)

    return HealthResponse(
        status="healthy",
        version=PROJECT_VERSION,
        environment=settings.app_env,
        db_status="healthy",
        storage={
            "assets": assets_count,
            "scans": scans_count,
        },
    )
