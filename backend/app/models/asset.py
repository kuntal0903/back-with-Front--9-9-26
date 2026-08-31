"""
app/models/asset.py

Domain model representing an attack surface asset.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Asset(BaseModel):
    """
    Represents a unique asset discovered on the attack surface (domain, IP, port, URL, etc.).
    Normalized to avoid duplicates.
    """

    asset_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the asset. Typically a UUID or derived from target/type.",
    )
    asset_type: str = Field(
        ...,
        description="The type of the asset (e.g., 'domain', 'ip_address', 'network_port').",
    )
    original_value: str = Field(
        ...,
        description="The original unnormalized value as first observed.",
    )
    normalized_value: str = Field(
        ...,
        description="The canonical normalized representation of the asset value.",
    )
    status: str = Field(
        default="confirmed",
        description="Asset validation status: confirmed | detected | inferred | unknown | failed.",
    )
    source_tool: str = Field(
        ...,
        description="The scanner tool that first discovered this asset.",
    )
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the asset was first discovered.",
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the asset was last seen during scans.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured key-value metadata specific to the asset type.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "asset_id": "asset-1234",
                    "asset_type": "ip_address",
                    "original_value": "192.0.2.1",
                    "normalized_value": "192.0.2.1",
                    "status": "confirmed",
                    "source_tool": "dns_scan",
                    "first_seen": "2026-08-26T09:00:00Z",
                    "last_seen": "2026-08-26T09:00:00Z",
                    "metadata": {},
                }
            ]
        }
    }
