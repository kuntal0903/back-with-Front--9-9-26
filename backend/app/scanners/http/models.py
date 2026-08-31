"""
app/scanners/http/models.py

Pydantic models representing structured data for the HTTP/HTTPS Scanner.
"""

from typing import Any
from pydantic import BaseModel, Field


class HttpRedirectStep(BaseModel):
    """
    Represents a single step in an HTTP redirect chain.
    """

    url: str = Field(..., description="The redirect location URL.")
    status_code: int = Field(..., description="HTTP redirect status code (e.g., 301, 302).")
    headers: dict[str, str] = Field(..., description="Response headers returned by the redirect.")


class HttpDetails(BaseModel):
    """
    Represents the full metadata resolved from querying a specific HTTP/HTTPS endpoint.
    """

    url: str = Field(..., description="Final request URL resolved.")
    status_code: int | None = Field(default=None, description="HTTP status code (e.g. 200, 404). None if transport failed.")
    transport_status: str = Field(default="success", description="Transport outcome: success | timeout | connection_refused | dns_failure | tls_error.")
    headers: dict[str, str] = Field(default_factory=dict, description="Raw response headers mapping.")
    http_version: str | None = Field(default=None, description="Negotiated HTTP protocol version (e.g. 'HTTP/1.1', 'HTTP/2').")
    server_product: str | None = Field(default=None, description="Server product software name if explicitly exposed.")
    server_version: str | None = Field(default=None, description="Server product version string if explicitly exposed.")
    content_type: str | None = Field(default=None, description="Response Content-Type header value.")
    title: str | None = Field(default=None, description="Parsed HTML page title (null if absent).")
    body_size_bytes: int = Field(default=0, description="Size of the raw body payload in bytes.")
    redirect_chain: list[HttpRedirectStep] = Field(
        default_factory=list,
        description="Chronological redirect history chain.",
    )
    cookies: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Parsed cookie metadata list (name, domain, path, secure, httponly, samesite).",
    )
    security_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Observed security-related response headers.",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Extracted HTML meta fields (e.g., description, generator).",
    )
    response_time_seconds: float = Field(..., description="Time taken to get the complete response.")
    ssl_verified: bool = Field(default=True, description="True if SSL verification succeeded during request.")


class HttpRecord(BaseModel):
    """
    Standard scanner output record for HTTP/HTTPS targets.
    """

    port: int = Field(..., ge=1, le=65535, description="Port scanned.")
    scheme: str = Field(..., description="Endpoint URL scheme: http | https.")
    details: HttpDetails = Field(..., description="Collected HTTP response metadata.")
