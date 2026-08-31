"""
app/scanners/dns/models.py

Pydantic models representing structured data for the DNS Scanner.
"""

from typing import Any

from pydantic import BaseModel, Field


class DnsRecord(BaseModel):
    """
    Represents a single DNS record resolved from target name query.
    """

    record_type: str = Field(
        ...,
        description="The type of the DNS record (e.g., 'A', 'AAAA', 'CNAME', 'MX', 'TXT').",
    )
    value: str = Field(
        ...,
        description="The resolved value of the record (e.g. resolved IP address, mail server domain).",
    )
    ttl: int = Field(
        ...,
        description="Time-To-Live duration in seconds.",
    )
    preference: int | None = Field(
        default=None,
        description="Record priority preference (applicable for MX records).",
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Record-type specific optional metadata parameters (e.g., SOA serial, CAA tag flags).",
    )
