"""
app/models/results.py

Domain model representing aggregated scan results.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.models.asset import Asset
from app.models.evidence import Evidence
from app.models.relationship import Relationship
from app.schemas.scan_request import TargetInfo


class ScanResult(BaseModel):
    """
    Represents the full aggregated attack surface result for a scan.
    Combines targets, discovered assets, relationships, supporting evidence, and errors.
    """

    scan_id: str = Field(..., description="Unique identifier for the scan.")
    target: TargetInfo = Field(..., description="Processed target information.")
    assets: list[Asset] = Field(
        default_factory=list,
        description="All unique assets discovered during the scan.",
    )
    relationships: list[Relationship] = Field(
        default_factory=list,
        description="Directed relationships between the discovered assets.",
    )
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="Traceable supporting evidence gathered during target scanning.",
    )
    errors: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured scanner execution errors.",
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the overall scan started.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="Timestamp when the scan completed. None if still running.",
    )
