"""
app/models/scan.py

Domain model representing a parent scan record.
"""

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from app.core.constants import SCAN_STATUS_CREATED
from app.schemas.scan_request import TargetInfo


class Scan(BaseModel):
    """
    Represents a target scan request lifecycle and execution state.
    """

    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the scan.",
    )
    target: TargetInfo = Field(
        ...,
        description="Preprocessed and authorized target info.",
    )
    status: str = Field(
        default=SCAN_STATUS_CREATED,
        description="Overall scan execution state: created | queued | running | completed | failed | partial_failure.",
    )
    mode: str = Field(
        ...,
        description="Selected scan mode: individual | selected | full.",
    )
    scans: list[str] = Field(
        default_factory=list,
        description="List of selected scan tool IDs.",
    )
    progress: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Progress percentage (0 to 100).",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the scan record was created.",
    )
    started_at: datetime | None = Field(
        default=None,
        description="Timestamp when the execution started.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="Timestamp when the execution finished.",
    )
    message: str | None = Field(
        default=None,
        description="Lifecycle status messages (e.g. error details, phase changes).",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "scan_id": "scan-1234",
                    "target": {
                        "original": "example.com",
                        "normalized": "example.com",
                        "target_type": "domain",
                    },
                    "status": "queued",
                    "mode": "full",
                    "scans": ["dns_scan"],
                    "progress": 0,
                    "created_at": "2026-08-26T09:00:00Z",
                    "started_at": None,
                    "completed_at": None,
                    "message": None,
                }
            ]
        }
    }
