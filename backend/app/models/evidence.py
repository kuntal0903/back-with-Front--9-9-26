"""
app/models/evidence.py

Domain model representing supporting evidence for a scan result or discovered asset.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.core.constants import CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM


class Evidence(BaseModel):
    """
    Represents technical evidence supporting a discovered asset, relationship, or detection.
    
    Every important scan output should preserve this to enable traceability.
    """

    source_tool: str = Field(
        ...,
        description="The scanner tool that observed the evidence (e.g., 'dns_scan').",
    )
    discovery_method: str = Field(
        ...,
        description="The mechanism used to collect the evidence (e.g., 'dns_query', 'http_header').",
    )
    raw_evidence: Any = Field(
        ...,
        description="The raw payload, string, or structured object obtained from the target.",
    )
    confidence: str = Field(
        default=CONFIDENCE_HIGH,
        description="Confidence level of the detection: low | medium | high.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the evidence was collected.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "source_tool": "technology_detection",
                    "discovery_method": "http_header",
                    "raw_evidence": "server: nginx/1.18.0",
                    "confidence": "high",
                    "timestamp": "2026-08-26T09:00:00Z",
                }
            ]
        }
    }
