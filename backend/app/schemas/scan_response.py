"""
app/schemas/scan_response.py

Pydantic schemas for scan API responses.

Defines:
  - ScanCreatedResponse — returned by POST /api/v1/scans
  - ScanStatusResponse  — returned by GET /api/v1/scans/{scan_id}
  - ScanResultsResponse — returned by GET /api/v1/scans/{scan_id}/results
"""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.scan_request import TargetInfo


class ScanCreatedResponse(BaseModel):
    """
    Returned immediately after a scan is accepted via POST /api/v1/scans.

    The scan runs in the background. Callers should poll
    GET /api/v1/scans/{scan_id} for status updates.
    """

    scan_id: str = Field(description="Unique identifier for this scan.")
    status: str = Field(description="Initial scan status, typically 'queued'.")
    target: TargetInfo = Field(description="Processed target information.")
    created_at: datetime = Field(description="Timestamp when the scan was created.")
    message: str | None = Field(
        default=None,
        description="Optional human-readable status message.",
    )

    model_config = {"json_schema_extra": {"examples": [
        {
            "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "status": "queued",
            "target": {
                "original": "example.com",
                "normalized": "example.com",
                "target_type": "domain",
            },
            "created_at": "2026-08-26T09:00:00Z",
            "message": None,
        }
    ]}}


class ScanStatusResponse(BaseModel):
    """
    Returned by GET /api/v1/scans/{scan_id}.

    Reflects the current lifecycle state of a running or completed scan.
    """

    scan_id: str
    status: str
    target: TargetInfo | None = None
    progress: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Approximate completion percentage (0–100). None when not applicable.",
    )
    created_at: datetime | None = None
    completed_at: datetime | None = None
    message: str | None = None


class ToolResultSummary(BaseModel):
    """Summary of results from one individual scan tool."""

    tool: str
    status: str
    result_count: int = 0
    error_count: int = 0


class ScanResultsResponse(BaseModel):
    """
    Returned by GET /api/v1/scans/{scan_id}/results.

    Contains the aggregated results from all completed scan tools.
    The exact shape of 'results' will be expanded as scanners are implemented.
    """

    scan_id: str
    status: str
    target: TargetInfo | None = None
    tool_summaries: list[ToolResultSummary] = Field(
        default_factory=list,
        description="Per-tool result summaries.",
    )
    results: list[dict] = Field(
        default_factory=list,
        description="Raw scan results. Schema evolves as scanners are added.",
    )
    errors: list[dict] = Field(
        default_factory=list,
        description="Structured errors from any failed scan tools.",
    )
    created_at: datetime | None = None
    completed_at: datetime | None = None
