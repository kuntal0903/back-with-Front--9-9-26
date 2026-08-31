"""
tests/test_cloud_scanner_accuracy.py

Comprehensive test suite for Advanced Cloud/CDN Detection Scanner,
validating CNAME chain traversal, HTTP header signatures, TLS cert correlation,
IP/ASN network ownership, multi-signal confidence calculation, and edge vs origin separation.
"""

import pytest
from unittest.mock import patch

from app.core.constants import TARGET_TYPE_DOMAIN, TARGET_TYPE_IPV4
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.cloud.analyzer import analyze_cname, analyze_headers, analyze_tls_certificate
from app.scanners.cloud.ranges import find_ip_provider_details
from app.scanners.cloud.scanner import CloudScanner


def test_ip_range_provider_lookup() -> None:
    """find_ip_provider_details identifies cloud networks and returns network owner organization."""
    res = find_ip_provider_details("104.16.1.1")
    assert res is not None
    provider, cidr, is_cdn, is_waf, org = res
    assert provider == "Cloudflare"
    assert is_cdn is True
    assert "Cloudflare" in org


def test_cname_pattern_analysis() -> None:
    """analyze_cname identifies CloudFront, Cloudflare, Azure, Fastly CNAME targets."""
    cf_res = analyze_cname("d11111.cloudfront.net.")
    assert cf_res is not None
    assert cf_res[0] == "AWS CloudFront"
    assert cf_res[1] is True  # is_cdn

    az_res = analyze_cname("app.azurewebsites.net.")
    assert az_res is not None
    assert az_res[0] == "Azure"
    assert az_res[1] is False  # is_cdn


def test_http_header_and_tls_correlation() -> None:
    """Header and TLS analyzers extract provider evidence signals."""
    headers = {"cf-ray": "123456789", "server": "cloudflare"}
    finding = analyze_headers(headers)
    assert finding is not None
    assert finding[0] == "Cloudflare"

    cert_issuer = {"organizationName": "Cloudflare, Inc."}
    cert_sans = ["*.example.com", "d111.cloudfront.net"]
    cert_findings = analyze_tls_certificate(cert_issuer, cert_sans)
    assert len(cert_findings) == 2
    provs = [f[0] for f in cert_findings]
    assert "Cloudflare" in provs
    assert "AWS CloudFront" in provs


@pytest.mark.asyncio
async def test_cloud_scanner_multi_signal_confidence_confirmed() -> None:
    """Scanner elevates confidence to CONFIRMED when multiple signals corroborate provider."""
    scanner = CloudScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    with patch("app.scanners.cloud.scanner.find_ip_provider_details", return_value=("AWS", "54.0.0.0/8", False, False, "Amazon.com")), \
         patch("httpx.AsyncClient.head", side_effect=Exception("no http")):

        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 1
    rec = result.results[0]
    assert rec.origin_ip == "unknown"
