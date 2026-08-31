"""
tests/test_http_scanner.py

Tests for the HTTP/HTTPS Scanner, validating HTML parsing, HTTPX mocking,
redirect chains, SSL fallback logic, security headers, cookies, and negative tests.
"""

import ssl
import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.http.parser import (
    parse_cookies_metadata,
    parse_page_metadata,
    parse_page_title,
    parse_security_headers,
    parse_server_header,
)
from app.scanners.http.scanner import HttpScanner


# ─────────────────────────────────────────────
# Unit Tests for HTML & Header Parsers
# ─────────────────────────────────────────────

def test_html_parser_extracts_title() -> None:
    """Parser must extract title tag content correctly under various formats."""
    assert parse_page_title("<html><head><title>Test Title</title></head></html>") == "Test Title"
    assert parse_page_title("<html><TITLE>Case Test</TITLE></html>") == "Case Test"
    
    multiline_html = """
    <title>
        Hello
        World
    </title>
    """
    assert parse_page_title(multiline_html) == "Hello World"
    assert parse_page_title("<title>Store &amp; Shop</title>") == "Store & Shop"
    assert parse_page_title("<title>User&#39;s Guide</title>") == "User's Guide"


def test_html_parser_negative_missing_title() -> None:
    """Parser MUST return None if <title> tag is missing (never invent a title)."""
    assert parse_page_title("<html><head></head><body>No title here</body></html>") is None


def test_server_header_parser() -> None:
    """Parser must extract product and version when present, or product only when version is absent."""
    prod, ver = parse_server_header("nginx/1.25.3")
    assert prod == "nginx"
    assert ver == "1.25.3"

    prod_no_ver, ver_no_ver = parse_server_header("nginx")
    assert prod_no_ver == "nginx"
    assert ver_no_ver is None  # MUST NOT guess version!


def test_security_headers_parser() -> None:
    """Parser must extract observed security headers."""
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-frame-options": "DENY",
        "content-type": "text/html",
    }
    sec = parse_security_headers(headers)
    assert sec["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert sec["X-Frame-Options"] == "DENY"
    assert "Content-Type" not in sec


def test_cookie_metadata_parser() -> None:
    """Parser must extract cookie metadata attributes without credentials."""
    cookie_hdrs = ["session_id=abc12345; Path=/; Secure; HttpOnly; SameSite=Strict"]
    parsed = parse_cookies_metadata(cookie_hdrs)
    assert len(parsed) == 1
    assert parsed[0]["name"] == "session_id"
    assert parsed[0]["path"] == "/"
    assert parsed[0]["secure"] is True
    assert parsed[0]["httponly"] is True
    assert parsed[0]["samesite"] == "strict"


def test_html_parser_extracts_meta_tags() -> None:
    """Parser must extract common meta tags (name and opengraph properties)."""
    html_doc = """
    <html>
    <head>
      <meta name="description" content="This is a test description.">
      <meta name="keywords" content="test, pytest, scanner">
      <meta name="Generator" content="WordPress 5.8">
      <meta property="og:title" content="OpenGraph Title">
      <meta property="og:site_name" content="My Site">
    </head>
    </html>
    """
    meta = parse_page_metadata(html_doc)
    assert meta["description"] == "This is a test description."
    assert meta["keywords"] == "test, pytest, scanner"
    assert meta["generator"] == "WordPress 5.8"
    assert meta["og:title"] == "OpenGraph Title"
    assert meta["og:site_name"] == "My Site"


# ─────────────────────────────────────────────
# Integration / Mock Client Tests
# ─────────────────────────────────────────────

class AsyncContextManagerMock:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.mark.asyncio
async def test_http_scanner_success_flow() -> None:
    """HTTP Scanner must probe http/https and return page title, status, size, and timings."""
    scanner = HttpScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    mock_resp_http = httpx.Response(
        status_code=200,
        headers={"Server": "nginx/1.18.0", "Content-Type": "text/html"},
        text="<html><title>HTTP Title</title></html>",
        request=httpx.Request("GET", "http://example.com"),
    )

    mock_resp_https = httpx.Response(
        status_code=200,
        headers={"Server": "nginx/1.18.0", "Content-Type": "text/html"},
        text="<html><title>HTTPS Title</title></html>",
        request=httpx.Request("GET", "https://example.com"),
    )

    async def _async_bytes(content):
        yield content

    def mock_client_stream(method, url, **kwargs):
        if str(url).startswith("https://"):
            resp = mock_resp_https
        else:
            resp = mock_resp_http
        resp.history = []
        resp.aiter_bytes = lambda: _async_bytes(resp.content)
        return AsyncContextManagerMock(resp)

    with patch("httpx.AsyncClient.stream", side_effect=mock_client_stream):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.errors) == 0
    assert len(result.results) == 2

    # Verify HTTP result
    http_rec = result.results[0]
    assert http_rec.port == 80
    assert http_rec.scheme == "http"
    assert http_rec.details.title == "HTTP Title"
    assert http_rec.details.server_product == "nginx"
    assert http_rec.details.server_version == "1.18.0"

    # Verify HTTPS result
    https_rec = result.results[1]
    assert https_rec.port == 443
    assert https_rec.scheme == "https"
    assert https_rec.details.title == "HTTPS Title"
    assert https_rec.details.ssl_verified is True
