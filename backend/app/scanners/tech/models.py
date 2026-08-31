"""
app/scanners/tech/models.py

Pydantic models representing structured data for the Technology Detection Scanner.
"""

from pydantic import BaseModel, Field


class TechEvidence(BaseModel):
    """
    Represents an individual observable piece of evidence for technology detection.
    """

    type: str = Field(
        ...,
        description="Evidence type: http_header | meta_tag | script_src | stylesheet_href | asset_path | cookie_name | html_pattern | dom_pattern | response_behavior",
    )
    source: str = Field(..., description="Exact field or resource source name (e.g. 'header:server', 'meta:generator').")
    value: str = Field(..., description="Observed raw or matched value string.")
    indicator_pattern: str = Field(..., description="Regex or pattern that matched this evidence.")


class DetectedTech(BaseModel):
    """
    Represents an individual technology identified on a target endpoint.
    """

    name: str = Field(..., description="Name of the detected technology (e.g., 'WordPress', 'Cloudflare').")
    category: str = Field(
        ...,
        description="Technology category classification: cms | web_server | reverse_proxy | cdn | waf | backend_framework | frontend_framework | js_library | analytics | web_components | programming_language | infrastructure.",
    )
    version: str | None = Field(default=None, description="Software version string if directly parsed/verified. None if unknown.")
    status: str = Field(default="detected", description="Detection status: detected | unknown | conflicting.")
    confidence: str = Field(
        ...,
        description="Confidence of the fingerprint detection: low | medium | high.",
    )
    evidence: list[TechEvidence] = Field(
        default_factory=list,
        description="Structured list of observable evidence supporting this detection.",
    )
    detection_methods: list[str] = Field(
        default_factory=list,
        description="List of detection method categories used (e.g., ['http_header', 'meta_tag']).",
    )
    matched_indicators: list[str] = Field(
        default_factory=list,
        description="Summary list of specific matched indicators for backwards compatibility.",
    )


class TechRecord(BaseModel):
    """
    Standard scanner output record for Technology Detection.
    """

    port: int = Field(..., ge=1, le=65535, description="Probed port number.")
    url: str = Field(..., description="Target URL probed for technology.")
    technologies: list[DetectedTech] = Field(
        default_factory=list,
        description="List of all detected technologies on this endpoint.",
    )
