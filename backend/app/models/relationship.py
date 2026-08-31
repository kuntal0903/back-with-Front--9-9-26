"""
app/models/relationship.py

Domain model representing relationships between assets.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Relationship(BaseModel):
    """
    Directed relationship connecting two assets (e.g., domain resolves_to ip_address).
    """

    source_asset_id: str = Field(
        ...,
        description="The asset ID of the source asset.",
    )
    relationship_type: str = Field(
        ...,
        description="The type of link (e.g., 'resolves_to', 'exposes', 'serves').",
    )
    target_asset_id: str = Field(
        ...,
        description="The asset ID of the target asset.",
    )
    source_tool: str = Field(
        ...,
        description="The scanner tool that discovered this relationship.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the relationship was discovered.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "source_asset_id": "domain-example-com",
                    "relationship_type": "resolves_to",
                    "target_asset_id": "ip-192-0-2-1",
                    "source_tool": "dns_scan",
                    "timestamp": "2026-08-26T09:00:00Z",
                }
            ]
        }
    }
