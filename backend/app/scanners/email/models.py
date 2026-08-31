"""
app/scanners/email/models.py

Pydantic models representing structured data for the Email Security Scanner.
"""

from pydantic import BaseModel, Field


class MxHostDetail(BaseModel):
    """
    Detailed metadata for an individual Mail Exchange (MX) host and its resolved IP targets.
    """

    hostname: str = Field(..., description="MX server hostname.")
    priority: int = Field(..., description="MX preference priority value.")
    ipv4_addresses: list[str] = Field(default_factory=list, description="Resolved IPv4 (A) addresses.")
    ipv6_addresses: list[str] = Field(default_factory=list, description="Resolved IPv6 (AAAA) addresses.")
    ptr_records: list[str] = Field(default_factory=list, description="Reverse DNS (PTR) hostnames.")
    resolution_status: str = Field(default="resolved", description="Resolution status: resolved | no_ip | dns_error.")


class SpfDetails(BaseModel):
    """
    Parsed results, mechanism structure, and syntax validation of the SPF policy.
    """

    record_found: bool = Field(default=False, description="True if at least one SPF record was found.")
    records: list[str] = Field(default_factory=list, description="Raw list of all SPF TXT records discovered.")
    is_valid: bool = Field(default=False, description="True if syntax compliance checks pass.")
    has_duplicates: bool = Field(default=False, description="True if multiple SPF records are configured.")
    policy_qualifier: str | None = Field(default=None, description="The 'all' qualifier found (e.g., '-all', '~all').")
    strength: str = Field(
        default="none",
        description="Policy enforcement strength rating: strong | weak | none.",
    )
    mechanisms: list[str] = Field(default_factory=list, description="Extracted mechanism tokens (e.g., ip4:1.2.3.4, mx, include:...).")
    includes: list[str] = Field(default_factory=list, description="Extracted SPF include domain names.")
    redirect: str | None = Field(default=None, description="Extracted SPF redirect domain name.")
    lookup_count: int = Field(default=0, description="Count of DNS-querying mechanisms present in the policy.")
    is_truncated: bool = Field(default=False, description="True if mechanism count exceeds maximum RFC 7208 lookup limit (10).")
    errors: list[str] = Field(default_factory=list, description="Critical syntactic compliance errors.")
    warnings: list[str] = Field(default_factory=list, description="Policy advice / insecure setup warnings.")


class DmarcDetails(BaseModel):
    """
    Parsed results and policy enforcement metrics of the DMARC record.
    """

    record_found: bool = Field(default=False, description="True if a DMARC record was found.")
    records: list[str] = Field(default_factory=list, description="Raw list of all DMARC TXT records discovered.")
    is_valid: bool = Field(default=False, description="True if syntax compliance checks pass.")
    has_duplicates: bool = Field(default=False, description="True if multiple DMARC records are configured.")
    policy: str | None = Field(default=None, description="Active apex policy directive (p=none | quarantine | reject).")
    subdomain_policy: str | None = Field(default=None, description="Active subdomain policy directive (sp=none | quarantine | reject).")
    percentage: int = Field(default=100, description="DMARC rule application percentage (pct value, defaults to 100).")
    alignment_dkim: str = Field(default="r", description="DKIM alignment mode: r (relaxed) | s (strict).")
    alignment_spf: str = Field(default="r", description="SPF alignment mode: r (relaxed) | s (strict).")
    report_interval: int | None = Field(default=None, description="Reporting interval in seconds (ri).")
    failure_options: str | None = Field(default=None, description="Failure reporting options (fo tag).")
    aggregate_reports: list[str] = Field(default_factory=list, description="Aggregate reporting target URIs (rua).")
    forensic_reports: list[str] = Field(default_factory=list, description="Forensic reporting target URIs (ruf).")
    errors: list[str] = Field(default_factory=list, description="Critical DMARC syntax compliance errors.")
    warnings: list[str] = Field(default_factory=list, description="Policy deployment warnings (e.g., policy='none').")


class DkimSelectorResult(BaseModel):
    """
    Structured metadata for a single DKIM selector TXT query result.
    """

    selector: str = Field(..., description="Selector name queried (e.g., 'default', 'google').")
    raw_record: str = Field(..., description="Raw TXT record returned.")
    version: str | None = Field(default=None, description="DKIM version (e.g., 'DKIM1').")
    key_type: str = Field(default="rsa", description="Key type (k tag, default 'rsa').")
    public_key: str | None = Field(default=None, description="Base64 public key string (p tag).")
    is_valid: bool = Field(default=True, description="True if DKIM record syntax is valid.")


class DkimDetails(BaseModel):
    """
    Discovered DKIM selectors and key parsing findings.
    """

    selectors_checked: list[str] = Field(default_factory=list, description="DKIM selectors checked during discovery.")
    selectors_found: dict[str, str] = Field(
        default_factory=dict,
        description="Discovered selectors mapping selector names to their raw TXT values.",
    )
    parsed_selectors: list[DkimSelectorResult] = Field(
        default_factory=list,
        description="Structured key details for discovered DKIM selectors.",
    )


class MtaStsDetails(BaseModel):
    """
    Parsed results of MTA-STS policy endpoint (https://mta-sts.<domain>/.well-known/mta-sts.txt).
    """

    found: bool = Field(default=False, description="True if MTA-STS policy was successfully fetched.")
    url: str | None = Field(default=None, description="MTA-STS policy endpoint URL.")
    status_code: int | None = Field(default=None, description="HTTP status code of the policy request.")
    version: str | None = Field(default=None, description="MTA-STS version (STSv1).")
    mode: str | None = Field(default=None, description="MTA-STS policy mode: enforce | testing | none.")
    mx_patterns: list[str] = Field(default_factory=list, description="Allowed MX hostname patterns.")
    max_age: int | None = Field(default=None, description="Policy max-age cache lifetime in seconds.")
    errors: list[str] = Field(default_factory=list, description="Parsing or fetching errors.")


class TlsRptDetails(BaseModel):
    """
    Parsed results of TLS-RPT record (_smtp._tls.<domain>).
    """

    found: bool = Field(default=False, description="True if TLS-RPT TXT record was found.")
    record: str | None = Field(default=None, description="Raw TLS-RPT TXT record value.")
    policy: str | None = Field(default=None, description="TLS-RPT version flag (v=TLSRPT1).")
    report_destinations: list[str] = Field(default_factory=list, description="Reporting target URIs (rua).")
    errors: list[str] = Field(default_factory=list, description="TLS-RPT syntax errors.")


class SmtpDetails(BaseModel):
    """
    Controlled protocol probe metrics of an MX host's SMTP service.
    """

    mx_host: str = Field(..., description="Target MX hostname probed.")
    ip_address: str | None = Field(default=None, description="IP address connected to.")
    port: int = Field(default=25, description="Port connected to.")
    banner: str | None = Field(default=None, description="Observed SMTP greeting banner.")
    supports_starttls: bool = Field(default=False, description="True if server advertises STARTTLS capability in EHLO.")
    connection_status: str = Field(default="unknown", description="Connection lifecycle status: success | refused | timeout | error.")


class EmailRecord(BaseModel):
    """
    Standard scanner output record containing complete email infrastructure and policy findings.
    """

    domain: str = Field(..., description="Apex domain targeted.")
    dns_status: str = Field(default="VALID_MX", description="Overall MX DNS status: VALID_MX | NO_MX_RECORD | DNS_ERROR | NXDOMAIN | TIMEOUT.")
    mx_records: list[str] = Field(default_factory=list, description="List of MX hostname strings (backwards compatibility).")
    mx_details: list[MxHostDetail] = Field(default_factory=list, description="Detailed MX host resolution records.")
    spf: SpfDetails = Field(default_factory=SpfDetails, description="SPF policy findings.")
    dmarc: DmarcDetails = Field(default_factory=DmarcDetails, description="DMARC policy findings.")
    dkim: DkimDetails = Field(default_factory=DkimDetails, description="DKIM selectors findings.")
    mta_sts: MtaStsDetails = Field(default_factory=MtaStsDetails, description="MTA-STS policy findings.")
    tls_rpt: TlsRptDetails = Field(default_factory=TlsRptDetails, description="TLS-RPT record findings.")
    smtp_details: list[SmtpDetails] = Field(default_factory=list, description="Controlled SMTP protocol observation records.")
