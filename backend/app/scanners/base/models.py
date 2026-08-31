"""
app/scanners/base/models.py

Pydantic schemas representing input and output constraints for all scan tools.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.models.evidence import Evidence
from app.schemas.scan_request import TargetInfo


class ScannerInput(BaseModel):
    """
    Standard input model passed to all scanners.
    """

    target: TargetInfo = Field(..., description="Processed target information.")
    configuration: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific configuration overrides (e.g. custom ports, timeouts).",
    )


class ScannerErrorDetail(BaseModel):
    """
    Represents structured details about a tool execution error.
    """

    error_type: str = Field(..., description="Machine-readable error type identifier.")
    message: str = Field(..., description="Human-readable error description.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the error occurred.",
    )


class ScannerResult(BaseModel):
    """
    Standard output model returned by all scanner executions.
    """

    tool: str = Field(..., description="Identifier name of the scan tool.")
    status: str = Field(
        ...,
        description="Tool execution status: completed | failed | unknown | not_tested.",
    )
    target: TargetInfo = Field(..., description="Copy of the input target info.")
    results: list[Any] = Field(
        default_factory=list,
        description="List of specific asset/configuration findings discovered by this tool.",
    )
    errors: list[ScannerErrorDetail] = Field(
        default_factory=list,
        description="Any errors encountered during tool execution.",
    )
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="Supporting evidence collected by this tool.",
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when this tool started execution.",
    )
    completed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when this tool finished execution.",
    )
