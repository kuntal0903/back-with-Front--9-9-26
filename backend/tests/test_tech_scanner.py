"""
tests/test_tech_scanner.py

Tests for the Technology Detection Scanner, validating rules matching,
confidence ratings, and concurrent scanner execution lifecycle.
"""

import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.tech.fingerprinter import fingerprint_response
from app.scanners.tech.scanner import TechScanner


# ─────────────────────────────────────────────
# Unit Tests for Fingerprinting Rules
# ─────────────────────────────────────────────

def test_fingerprint_nginx_server() -> None:
    """Nginx signature should match server header and extract version."""
    headers = {"Server": "nginx/1.19.2", "Content-Type": "text/html"}
    detected = fingerprint_response(headers, "<html></html>", [])
    
    assert len(detected) == 1
    tech = detected[0]
    assert tech.name == "nginx"
    assert tech.category == "web_server"
    assert tech.version == "1.19.2"
    assert tech.confidence == "medium"  # Single indicator matching
    assert "header:server" in tech.matched_indicators


def test_fingerprint_wordpress_high_confidence() -> None:
    """WordPress signature should match multiple indicators and return high confidence."""
    headers = {"X-Powered-By": "WordPress"}
    html = """
    <html>
      <head>
        <meta name="generator" content="WordPress 5.8.1" />
        <link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css" />
      </head>
    </html>
    """
    detected = fingerprint_response(headers, html, ["wordpress_logged_in_xyz"])
    
    # Matches WordPress
    wp_matches = [t for t in detected if t.name == "WordPress"]
    assert len(wp_matches) == 1
    wp = wp_matches[0]
    assert wp.category == "cms"
    assert wp.version == "5.8.1"
    assert wp.confidence == "high"  # Multiple indicators matching (headers, html, cookie)
    assert len(wp.matched_indicators) >= 2


def test_fingerprint_cloudflare_cdn() -> None:
    """Cloudflare signature should match header and cookie indicators."""
    headers = {"Server": "cloudflare", "CF-Ray": "ray-12345"}
    detected = fingerprint_response(headers, "<html></html>", ["__cf_bm"])
    
    cf_matches = [t for t in detected if t.name == "Cloudflare"]
    assert len(cf_matches) == 1
    cf = cf_matches[0]
    assert cf.category == "cdn"
    assert cf.confidence == "high"
    assert "header:server" in cf.matched_indicators
    assert "cookie:__cf_bm" in cf.matched_indicators


def test_fingerprint_laravel_cookie() -> None:
    """Laravel signature should match session cookie indicator."""
    detected = fingerprint_response({}, "<html></html>", ["laravel_session"])
    assert len(detected) == 1
    assert detected[0].name == "Laravel"
    assert detected[0].category == "framework"
    assert "cookie:laravel_session" in detected[0].matched_indicators


def test_fingerprint_jquery_js_library() -> None:
    """jQuery signature should match HTML script tag and parse version."""
    html = '<html><script src="/js/jquery-3.5.1.min.js"></script></html>'
    detected = fingerprint_response({}, html, [])
    assert len(detected) == 1
    assert detected[0].name == "jQuery"
    assert detected[0].category == "js_library"
    assert detected[0].version == "3.5.1"


# ─────────────────────────────────────────────
# Scanner Mock Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tech_scanner_success_flow() -> None:
    """Tech Scanner must probe targets concurrently and return detected technologies."""
    scanner = TechScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    # Mock HTTP response containing Nginx, WordPress, and jQuery indicators
    mock_resp_http = httpx.Response(
        status_code=200,
        headers={"Server": "nginx/1.18.0", "X-Powered-By": "WordPress"},
        text='<html><script src="/jquery-3.6.0.js"></script></html>',
        request=httpx.Request("GET", "http://example.com"),
    )

    mock_resp_https = httpx.Response(
        status_code=200,
        headers={"Server": "nginx/1.18.0"},
        text="<html></html>",
        request=httpx.Request("GET", "https://example.com"),
    )

    async def mock_client_get(url, **kwargs):
        if url.startswith("https://"):
            return mock_resp_https
        return mock_resp_http

    with patch("httpx.AsyncClient.get", side_effect=mock_client_get):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.errors) == 0
    # Both HTTP (80) and HTTPS (443) should return records since both responded and matched nginx
    assert len(result.results) == 2

    # HTTP results: should find nginx, WordPress, jQuery
    http_rec = result.results[0]
    assert http_rec.port == 80
    tech_names = [t.name for t in http_rec.technologies]
    assert "nginx" in tech_names
    assert "WordPress" in tech_names
    assert "jQuery" in tech_names

    # HTTPS results: should find nginx only
    https_rec = result.results[1]
    assert https_rec.port == 443
    assert len(https_rec.technologies) == 1
    assert https_rec.technologies[0].name == "nginx"

    # Evidence mapping must exist for each detection
    # HTTP: nginx (1), WordPress (1), jQuery (1) -> 3
    # HTTPS: nginx (1) -> 1
    # Total = 4 evidence records
    assert len(result.evidence) == 4
