"""
app/scanners/service/models.py

Pydantic models representing structured data for the Service Identification Scanner.
"""

from typing import Any

from pydantic import BaseModel, Field


class ServiceRecord(BaseModel):
    """
    Represents service details resolved from probing an open port.
    """

    port: int = Field(..., ge=1, le=65535, description="Port number analyzed.")
    protocol: str = Field(..., description="Determined network service protocol (e.g., 'ssh', 'http', 'https', 'smtp', 'ftp', 'unknown').")
    software_name: str | None = Field(
        default=None,
        description="Identified software name (e.g., 'nginx', 'OpenSSH'). None if unrecognized.",
    )
    software_version: str | None = Field(
        default=None,
        description="Parsed software version string (e.g., '1.18.0', '8.4p1'). None if unrecognized.",
    )
    is_tls: bool = Field(
        default=False,
        description="Indicates if service communication is wrapped in TLS/SSL.",
    )
    alpn: str | None = Field(
        default=None,
        description="Negotiated TLS ALPN application protocol if available (e.g. 'h2', 'http/1.1').",
    )
    confidence: str = Field(
        default="high",
        description="Confidence level of service identification: 'high', 'medium', 'low'.",
    )
    raw_banner: str | None = Field(
        default=None,
        description="The raw payload or banner greeting collected from the server.",
    )
    extra_attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional parsed fields specific to the service (e.g. HTTP headers, SMTP domains).",
    )
