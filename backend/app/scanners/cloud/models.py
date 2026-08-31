"""
app/scanners/cloud/models.py

Pydantic models representing structured data for the Advanced Cloud/CDN Detection Scanner.
"""

from pydantic import BaseModel, Field


class NetworkOwnership(BaseModel):
    """
    IP address subnet and ASN network ownership metadata.
    """

    ip: str | None = Field(default=None, description="IP address analyzed.")
    asn: str | None = Field(default=None, description="Autonomous System Number (e.g., AS16509).")
    organization: str | None = Field(default=None, description="Network owner organization name (e.g. Amazon.com).")
    cidr: str | None = Field(default=None, description="Matched network CIDR block.")


class CdnFinding(BaseModel):
    """
    Identified Content Delivery Network (CDN) finding and evidence chain.
    """

    provider: str = Field(..., description="CDN provider name (e.g., Cloudflare, AWS CloudFront, Fastly, Akamai).")
    confidence: str = Field(default="LIKELY", description="Detection confidence: CONFIRMED | LIKELY | POSSIBLE.")
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence signals (CNAME, headers, cert).")


class WafFinding(BaseModel):
    """
    Identified Web Application Firewall (WAF) indicator finding and evidence chain.
    """

    provider: str = Field(..., description="WAF provider name (e.g., Cloudflare, AWS WAF, Imperva).")
    confidence: str = Field(default="LIKELY", description="Detection confidence: CONFIRMED | LIKELY | POSSIBLE.")
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence signals.")


class CloudFinding(BaseModel):
    """
    Identified Public Cloud / Hosting infrastructure finding.
    """

    provider: str = Field(..., description="Cloud provider name (e.g., AWS, GCP, Azure).")
    relationship: str = Field(default="NETWORK_OWNER", description="Relationship type: NETWORK_OWNER | SERVICE_PROVIDER.")
    confidence: str = Field(default="LIKELY", description="Detection confidence: CONFIRMED | LIKELY | POSSIBLE.")
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence signals.")


class CloudCdnRecord(BaseModel):
    """
    Standard scanner output record containing multi-signal Cloud, CDN, and WAF correlation findings.
    """

    target: str = Field(..., description="Target domain, hostname, or IP address probed.")
    is_cloud: bool = Field(default=False, description="True if target sits on public cloud infrastructure.")
    is_cdn: bool = Field(default=False, description="True if target sits behind a CDN.")
    is_waf: bool = Field(default=False, description="True if target exhibits WAF proxy signatures.")
    provider: str | None = Field(default=None, description="Primary identified provider (backwards compatibility).")
    detection_method: str | None = Field(default=None, description="Primary detection mechanism (backwards compatibility).")
    matched_evidence: str | None = Field(default=None, description="Primary evidence string (backwards compatibility).")
    network: NetworkOwnership | None = Field(default=None, description="Network ownership and ASN correlation.")
    cname_chain: list[str] = Field(default_factory=list, description="Complete observed DNS CNAME target chain.")
    cdn: CdnFinding | None = Field(default=None, description="Correlated CDN provider finding.")
    waf: WafFinding | None = Field(default=None, description="Correlated WAF provider finding.")
    cloud: CloudFinding | None = Field(default=None, description="Correlated Cloud provider finding.")
    observed_edge_ip: str | None = Field(default=None, description="Publicly observed edge IP address.")
    origin_ip: str = Field(default="unknown", description="Origin IP address if independently established (defaults to 'unknown').")
