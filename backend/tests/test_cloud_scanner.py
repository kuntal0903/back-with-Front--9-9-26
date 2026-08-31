"""
tests/test_cloud_scanner.py

Tests for the Cloud/CDN Detection Scanner, validating IP subnet mapping membership,
CNAME suffix regular expressions, HTTP header signatures, and mock connection pipelines.
"""

import httpx
import pytest
from unittest.mock import patch

from app.core.constants import TARGET_TYPE_DOMAIN, TARGET_TYPE_IPV4
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.cloud.analyzer import analyze_cname, analyze_headers
from app.scanners.cloud.ranges import find_ip_provider
from app.scanners.cloud.scanner import CloudScanner


# ─────────────────────────────────────────────
# Unit Tests for IP Ranges Member Matcher
# ─────────────────────────────────────────────

def test_find_ip_provider_cloudflare() -> None:
    """Matcher must map Cloudflare IP ranges to Cloudflare CDN."""
    res = find_ip_provider("104.16.12.34")
    assert res is not None
    provider, subnet, is_cdn = res
    assert provider == "Cloudflare"
    assert is_cdn is True
    assert "104.16.0.0/13" in subnet


def test_find_ip_provider_aws() -> None:
    """Matcher must map AWS IP ranges to AWS public cloud."""
    res = find_ip_provider("54.239.5.5")  # lies in 54.0.0.0/8
    assert res is not None
    provider, _, is_cdn = res
    assert provider == "AWS"
    assert is_cdn is False


def test_find_ip_provider_unrelated() -> None:
    """Matcher must return None for standard unrelated IP addresses."""
    assert find_ip_provider("8.8.8.8") is None
    assert find_ip_provider("invalid-ip") is None


# ─────────────────────────────────────────────
# Unit Tests for DNS CNAME & Headers Analyzer
# ─────────────────────────────────────────────

def test_analyze_cname_signatures() -> None:
    """Analyzer must map known CDN CNAME routing suffixes to provider names."""
    assert analyze_cname("d123.cloudfront.net.") == ("AWS CloudFront", True)
    assert analyze_cname("site.edgekey.net") == ("Akamai", True)
    assert analyze_cname("app.azurewebsites.net") == ("Azure", False)
    assert analyze_cname("unrelated.com") is None


def test_analyze_headers_signatures() -> None:
    """Analyzer must identify CDN provider servers or via tags in header dictionaries."""
    # Server Cloudflare
    cf_res = analyze_headers({"Server": "cloudflare", "CF-RAY": "123456"})
    assert cf_res is not None
    assert cf_res[0] == "Cloudflare"
    assert cf_res[1] is True

    # Via CloudFront
    cf_via = analyze_headers({"Via": "1.1 d111.cloudfront.net (CloudFront)", "Server": "nginx"})
    assert cf_via is not None
    assert cf_via[0] == "AWS CloudFront"
    assert cf_via[1] is True

    # Unrelated Server
    assert analyze_headers({"Server": "Apache/2.4.41"}) is None


# ─────────────────────────────────────────────
# Integration Scanner Mock Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cloud_scanner_ip_target() -> None:
    """Cloud Scanner must identify cloud providers directly if IP target is provided."""
    scanner = CloudScanner()
    target_info = TargetInfo(original="104.16.100.100", normalized="104.16.100.100", target_type=TARGET_TYPE_IPV4)
    scanner_input = ScannerInput(target=target_info)

    result = await scanner.execute(scanner_input)
    assert result.status == "completed"
    assert len(result.results) == 1
    
    rec = result.results[0]
    assert rec.provider == "Cloudflare"
    assert rec.is_cdn is True
    assert rec.detection_method == "ip_range"
    assert "104.16.0.0/13" in rec.matched_evidence


@pytest.mark.asyncio
async def test_cloud_scanner_domain_target_cname() -> None:
    """Cloud Scanner must resolve domain CNAME and classify provider accordingly."""
    scanner = CloudScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    async def mock_resolve(host, rtype):
        if rtype == "CNAME":
            # mock CNAME mapping answer
            class MockRdata:
                target = "d111.cloudfront.net."
            return [MockRdata()]
        return []

    # Patch DNS resolver CNAME and A lookups
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        # Patch HTTP calls to return empty so we test CNAME precedence
        with patch("httpx.AsyncClient.head", side_effect=Exception("HTTP connection failed")):
            with patch("httpx.AsyncClient.get", side_effect=Exception("HTTP connection failed")):
                result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 1
    
    rec = result.results[0]
    assert rec.provider == "AWS CloudFront"
    assert rec.is_cdn is True
    assert rec.detection_method == "dns_cname"
    assert "d111.cloudfront.net" in rec.matched_evidence
