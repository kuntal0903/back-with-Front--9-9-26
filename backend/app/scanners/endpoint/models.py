"""
app/scanners/endpoint/models.py

Pydantic models representing structured data for the Web Endpoint Discovery Scanner.
"""

from pydantic import BaseModel, Field


class EndpointRecord(BaseModel):
    """
    Represents an individual web page path, resource, form, or API endpoint discovered.
    """

    url: str = Field(..., description="The absolute normalized URL of the web endpoint.")
    status_code: int | None = Field(
        default=None,
        description="Observed HTTP response status code. None if static reference not yet verified.",
    )
    content_type: str | None = Field(
        default=None,
        description="The response content-type header (e.g. 'text/html', 'application/json').",
    )
    response_time_seconds: float | None = Field(
        default=None,
        description="Query response duration in seconds. None if static reference.",
    )
    parent_url: str | None = Field(
        default=None,
        description="The referrer or parent document URL where this endpoint was extracted.",
    )
    endpoint_type: str = Field(
        default="PAGE",
        description="Endpoint classification: PAGE | API | FORM | SCRIPT | STYLESHEET | IMAGE | MEDIA | OTHER_RESOURCE.",
    )
    discovery_source: str = Field(
        default="html_anchor",
        description="Discovery source: html_anchor | html_link | html_form | script_tag | resource_tag | robots_txt | sitemap_xml | javascript_static_reference.",
    )
    discovery_status: str = Field(
        default="DISCOVERED",
        description="Verification lifecycle status: DISCOVERED | VERIFIED_LIVE.",
    )
    http_method: str = Field(default="GET", description="Observed HTTP method (e.g. GET, POST).")
    query_parameters: list[str] = Field(
        default_factory=list,
        description="List of observed URL query parameter keys.",
    )
    form_inputs: list[dict[str, str]] | None = Field(
        default=None,
        description="Structured input names and types when endpoint_type == FORM.",
    )
