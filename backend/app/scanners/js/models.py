"""
app/scanners/js/models.py

Pydantic models representing structured data for the JavaScript Discovery Scanner.
"""

from pydantic import BaseModel, Field


class JsReference(BaseModel):
    """
    Represents an individual reference or endpoint extracted from JavaScript code.
    """

    value: str = Field(..., description="Original extracted string value or URL reference.")
    type: str = Field(
        ...,
        description="Reference type: api_endpoint | absolute_url | relative_path | websocket_url | hostname | external_domain | source_map | secret | library_identifier.",
    )
    source_file: str = Field(..., description="Script source URL or 'inline' for page scripts.")
    discovery_method: str = Field(default="javascript_static_analysis", description="Extraction method used.")
    status: str = Field(default="REFERENCED", description="Verification status: REFERENCED | partially_resolved.")
    http_method: str = Field(default="UNKNOWN", description="Observed HTTP method if request call (e.g. GET, POST, UNKNOWN).")
    confidence: str = Field(default="medium", description="Extraction confidence: high | medium | low.")
    resolution_base: str | None = Field(default=None, description="Base URL used to resolve relative paths.")
    resolved_reference: str | None = Field(default=None, description="Normalized resolved absolute URL if relative path.")


class JsScriptDetails(BaseModel):
    """
    Metadata and extracted findings for an individual JavaScript file or block analyzed.
    """

    script_url: str = Field(
        ...,
        description="The source URL of the script. Marked as 'inline' for page scripts.",
    )
    content_type: str | None = Field(default=None, description="HTTP Content-Type header of the script asset.")
    file_size_bytes: int | None = Field(default=None, description="Script file payload size in bytes.")
    is_minified: bool = Field(default=False, description="True if script appears to be minified.")
    source_map_url: str | None = Field(default=None, description="Extracted sourceMappingURL reference if present.")
    references: list[JsReference] = Field(
        default_factory=list,
        description="Structured list of all references extracted from this script.",
    )
    discovered_paths: list[str] = Field(
        default_factory=list,
        description="List of relative/absolute endpoints discovered (backwards compatibility).",
    )
    discovered_secrets: list[str] = Field(
        default_factory=list,
        description="List of potential API keys or secrets found (backwards compatibility).",
    )


class JsRecord(BaseModel):
    """
    Standard scanner output record containing JavaScript analysis findings.
    """

    origin_url: str = Field(..., description="The originating page URL scanned.")
    scripts: list[JsScriptDetails] = Field(
        default_factory=list,
        description="Collection of findings from script assets linked to this page.",
    )
