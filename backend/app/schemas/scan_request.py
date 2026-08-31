"""
app/schemas/scan_request.py

Pydantic schemas for scan API requests.

Defines:
  - TargetInfo — structured representation of a processed target
  - ScanRequest — the request body for POST /api/v1/scans
"""

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.core.constants import (
    TOOL_DNS_SCAN,
    TOOL_PORT_DISCOVERY,
    TOOL_SERVICE_IDENTIFICATION,
    TOOL_HTTP_SCAN,
    TOOL_TECHNOLOGY_DETECTION,
    TOOL_ENDPOINT_DISCOVERY,
    TOOL_JAVASCRIPT_DISCOVERY,
    TOOL_TLS_SCAN,
    TOOL_EMAIL_SECURITY,
    TOOL_CLOUD_CDN_DETECTION,
)

# All valid scan tool identifiers
VALID_SCAN_TOOLS: frozenset[str] = frozenset({
    TOOL_DNS_SCAN,
    TOOL_PORT_DISCOVERY,
    TOOL_SERVICE_IDENTIFICATION,
    TOOL_HTTP_SCAN,
    TOOL_TECHNOLOGY_DETECTION,
    TOOL_ENDPOINT_DISCOVERY,
    TOOL_JAVASCRIPT_DISCOVERY,
    TOOL_TLS_SCAN,
    TOOL_EMAIL_SECURITY,
    TOOL_CLOUD_CDN_DETECTION,
})


class TargetInfo(BaseModel):
    """
    Structured representation of a fully processed scan target.

    Preserved throughout the scan lifecycle so every result can be
    traced back to what the user originally submitted.
    """

    original: str = Field(
        description="The target exactly as submitted by the user."
    )
    normalized: str = Field(
        description="The canonical, normalized form of the target."
    )
    target_type: str = Field(
        description="Classified target type: domain | hostname | ipv4 | ipv6"
    )
    hostname: str | None = Field(
        default=None,
        description="Canonical hostname or domain if applicable."
    )
    ip: str | None = Field(
        default=None,
        description="Canonical IP address (IPv4 or IPv6) if applicable."
    )
    scheme: str | None = Field(
        default=None,
        description="URL scheme if provided (e.g. http, https)."
    )
    port: int | None = Field(
        default=None,
        description="Port number if provided in URL or target."
    )
    path: str | None = Field(
        default=None,
        description="URL path if provided."
    )
    scope: str = Field(
        default="in_scope",
        description="Target scope status (in_scope | out_of_scope)."
    )
    initial_asset: str | None = Field(
        default=None,
        description="Identified initial asset descriptor (e.g. domain:example.com, ip_address:192.0.2.10)."
    )

    model_config = {"json_schema_extra": {"examples": [
        {
            "original": "https://example.com:443/path",
            "normalized": "example.com",
            "target_type": "domain",
            "hostname": "example.com",
            "ip": None,
            "scheme": "https",
            "port": 443,
            "path": "/path",
            "scope": "in_scope",
            "initial_asset": "domain:example.com",
        }
    ]}}


class ScanRequest(BaseModel):
    """
    Request body for POST /api/v1/scans.

    Example — full scan:
        {"target": "example.com", "mode": "full"}

    Example — individual scan:
        {"target": "example.com", "mode": "individual", "scans": ["dns_scan"]}

    Example — selected scans:
        {"target": "example.com", "mode": "selected", "scans": ["dns_scan", "tls_scan"]}
    """

    target: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="The target to scan: domain, hostname, IPv4, or IPv6 address.",
        examples=["example.com", "192.0.2.1", "2001:db8::1"],
    )
    mode: Literal["individual", "selected", "full"] = Field(
        default="full",
        description=(
            "Scan mode. "
            "'individual' and 'selected' require the 'scans' field to be populated. "
            "'full' runs all applicable tools automatically."
        ),
    )
    scans: list[str] = Field(
        default_factory=list,
        description=(
            "Scan tool IDs to run. "
            "Required when mode is 'individual' or 'selected'. "
            "Ignored when mode is 'full'."
        ),
    )
    configuration: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional per-tool configuration overrides.",
    )

    @field_validator("scans")
    @classmethod
    def validate_scan_tool_ids(cls, scans: list[str]) -> list[str]:
        """Reject any unrecognized scan tool identifiers."""
        invalid = [s for s in scans if s not in VALID_SCAN_TOOLS]
        if invalid:
            raise ValueError(
                f"Unknown scan tool identifier(s): {invalid}. "
                f"Valid tools are: {sorted(VALID_SCAN_TOOLS)}"
            )
        return scans

    @field_validator("mode")
    @classmethod
    def validate_mode_scans_consistency(cls, mode: str) -> str:
        """Mode itself is validated by Literal — no extra logic needed here."""
        return mode

    def requires_scans_field(self) -> bool:
        """Return True when the mode requires the scans list to be non-empty."""
        return self.mode in ("individual", "selected")
