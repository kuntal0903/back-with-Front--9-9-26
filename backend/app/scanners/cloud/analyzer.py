"""
app/scanners/cloud/analyzer.py

Analyzes DNS CNAME patterns, HTTP response headers, and TLS certificates
to identify Cloud, CDN, and WAF providers and evidence signals.
"""

import re

# CNAME patterns: (regex, provider, is_cdn, is_waf)
_CNAME_PATTERNS = [
    (re.compile(r"\.cloudfront\.net$", re.IGNORECASE), "AWS CloudFront", True, False),
    (re.compile(r"\.amazonaws\.com$", re.IGNORECASE), "AWS", False, False),
    (re.compile(r"\.azureedge\.net$", re.IGNORECASE), "Azure Front Door", True, True),
    (re.compile(r"\.azurefd\.net$", re.IGNORECASE), "Azure Front Door", True, True),
    (re.compile(r"\.azurewebsites\.net$", re.IGNORECASE), "Azure", False, False),
    (re.compile(r"\.cloudflare\.net$", re.IGNORECASE), "Cloudflare", True, True),
    (re.compile(r"\.edgekey\.net$", re.IGNORECASE), "Akamai", True, False),
    (re.compile(r"\.edgesuite\.net$", re.IGNORECASE), "Akamai", True, False),
    (re.compile(r"\.akamai\.net$", re.IGNORECASE), "Akamai", True, False),
    (re.compile(r"\.fastly\.net$", re.IGNORECASE), "Fastly", True, False),
    (re.compile(r"\.fastly-edge\.com$", re.IGNORECASE), "Fastly", True, False),
    (re.compile(r"\.netlify\.app$", re.IGNORECASE), "Netlify", True, False),
    (re.compile(r"\.vercel\.app$", re.IGNORECASE), "Vercel", True, False),
    (re.compile(r"\.incapdns\.net$", re.IGNORECASE), "Imperva", True, True),
    (re.compile(r"\.sucuri\.net$", re.IGNORECASE), "Sucuri", True, True),
]


def analyze_cname(cname: str) -> tuple[str, bool] | None:
    """
    Evaluate a CNAME domain target to detect Cloud/CDN provider indicators.
    Returns (provider_name, is_cdn) for backwards compatibility.
    """
    cleaned = cname.strip().rstrip(".").lower()

    for pattern, provider, is_cdn, _ in _CNAME_PATTERNS:
        if pattern.search(cleaned):
            return provider, is_cdn

    return None


def analyze_cname_details(cname: str) -> tuple[str, bool, bool] | None:
    """
    Detailed CNAME lookup returning (provider_name, is_cdn, is_waf).
    """
    cleaned = cname.strip().rstrip(".").lower()

    for pattern, provider, is_cdn, is_waf in _CNAME_PATTERNS:
        if pattern.search(cleaned):
            return provider, is_cdn, is_waf

    return None


def analyze_headers(headers: dict[str, str]) -> tuple[str, bool, str] | None:
    """
    Evaluate HTTP response headers to detect Cloud/CDN signatures.
    Returns (provider, is_cdn, matching_header) for backwards compatibility.
    """
    norm_headers = {k.lower(): v.lower() for k, v in headers.items()}

    # 1. Direct header checks
    if "cf-ray" in norm_headers or "cf-cache-status" in norm_headers:
        return "Cloudflare", True, "cf-ray"
    if "x-amz-cf-id" in norm_headers or "x-amz-cf-pop" in norm_headers:
        return "AWS CloudFront", True, "x-amz-cf-id"
    if "x-azure-ref" in norm_headers:
        return "Azure Front Door", True, "x-azure-ref"

    # 2. Server header inspection
    server_val = norm_headers.get("server", "")
    if "cloudflare" in server_val:
        return "Cloudflare", True, "server: cloudflare"
    if "cloudfront" in server_val:
        return "AWS CloudFront", True, "server: cloudfront"
    if "gws" in server_val or "google" in server_val:
        return "GCP", False, f"server: {server_val}"
    if "microsoft-iis" in server_val:
        return "Azure", False, "server: microsoft-iis"

    # 3. Via header inspection
    via_val = norm_headers.get("via", "")
    if "cloudfront" in via_val:
        return "AWS CloudFront", True, f"via: {via_val}"
    if "fastly" in via_val:
        return "Fastly", True, f"via: {via_val}"
    if "akamai" in via_val:
        return "Akamai", True, f"via: {via_val}"

    # 4. Cache-Control/X-Cache headers inspection
    x_cache_val = norm_headers.get("x-cache", "")
    if "cloudfront" in x_cache_val:
        return "AWS CloudFront", True, f"x-cache: {x_cache_val}"
    if "fastly" in x_cache_val:
        return "Fastly", True, f"x-cache: {x_cache_val}"
    if "akamai" in x_cache_val:
        return "Akamai", True, f"x-cache: {x_cache_val}"

    return None


def analyze_headers_details(headers: dict[str, str]) -> list[tuple[str, bool, bool, str]]:
    """
    Detailed HTTP headers inspection returning list of (provider, is_cdn, is_waf, evidence_string).
    """
    norm_headers = {k.lower(): v.lower() for k, v in headers.items()}
    findings: list[tuple[str, bool, bool, str]] = []

    if "cf-ray" in norm_headers or "cf-cache-status" in norm_headers:
        findings.append(("Cloudflare", True, True, "header: cf-ray/cf-cache-status"))
    elif "server" in norm_headers and "cloudflare" in norm_headers["server"]:
        findings.append(("Cloudflare", True, True, "server: cloudflare"))

    if "x-amz-cf-id" in norm_headers or "x-amz-cf-pop" in norm_headers:
        findings.append(("AWS CloudFront", True, False, "header: x-amz-cf-id"))
    elif "via" in norm_headers and "cloudfront" in norm_headers["via"]:
        findings.append(("AWS CloudFront", True, False, "via: cloudfront"))
    elif "server" in norm_headers and "cloudfront" in norm_headers["server"]:
        findings.append(("AWS CloudFront", True, False, "server: cloudfront"))

    if "x-azure-ref" in norm_headers:
        findings.append(("Azure Front Door", True, True, "header: x-azure-ref"))

    server_val = norm_headers.get("server", "")
    if ("gws" in server_val or "google" in server_val) and not any(f[0] == "GCP" for f in findings):
        findings.append(("GCP", False, False, f"server: {server_val}"))
    if "microsoft-iis" in server_val and not any(f[0] in ("Azure", "Azure Front Door") for f in findings):
        findings.append(("Azure", False, False, "server: microsoft-iis"))

    return findings


def analyze_tls_certificate(issuer_dict: dict[str, str], sans: list[str]) -> list[tuple[str, bool, bool, str]]:
    """
    Correlate TLS Certificate Issuer and Subject Alternative Names (SANs) to infer infrastructure.
    """
    findings: list[tuple[str, bool, bool, str]] = []
    issuer_org = (issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "").lower()

    if "cloudflare" in issuer_org:
        findings.append(("Cloudflare", True, True, f"cert issuer: {issuer_org}"))
    elif "amazon" in issuer_org:
        findings.append(("AWS", False, False, f"cert issuer: {issuer_org}"))
    elif "microsoft" in issuer_org:
        findings.append(("Azure", False, False, f"cert issuer: {issuer_org}"))

    for san in sans:
        san_lower = san.lower()
        if "cloudfront.net" in san_lower:
            findings.append(("AWS CloudFront", True, False, f"cert SAN: {san}"))
        elif "azureedge.net" in san_lower or "azurefd.net" in san_lower:
            findings.append(("Azure Front Door", True, True, f"cert SAN: {san}"))

    return findings
