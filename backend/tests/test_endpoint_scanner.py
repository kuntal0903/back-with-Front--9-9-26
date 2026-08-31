"""
tests/test_endpoint_scanner.py

Tests for the Web Endpoint Discovery Scanner, validating links extraction,
scope policies, max depth rules, max page count constraints, and mock page crawls.
"""

import httpx
import pytest
from unittest.mock import AsyncMock, patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.endpoint.extractor import extract_html_links
from app.scanners.endpoint.scope import is_url_in_scope
from app.scanners.endpoint.scanner import EndpointScanner


# ─────────────────────────────────────────────
# Unit Tests for Link Extractor
# ─────────────────────────────────────────────

def test_link_extractor_relative_and_absolute() -> None:
    """Extractor must resolve relative links to absolute, and deduplicate outputs."""
    html = """
    <html>
      <a href="/about-us">About</a>
      <a href="https://example.com/pricing">Pricing</a>
      <a href="/about-us">Duplicate</a>
      <a href="mailto:info@example.com">Email</a>
      <a href="tel:+12345">Phone</a>
      <a href="javascript:void(0)">JS</a>
      <a href="#section-anchor">Anchor</a>
      <a href="/contact#form-fragment">Contact with fragment</a>
    </html>
    """
    links = extract_html_links("https://example.com/", html)
    assert len(links) == 3
    assert "https://example.com/about-us" in links
    assert "https://example.com/pricing" in links
    # Fragment stripped
    assert "https://example.com/contact" in links


# ─────────────────────────────────────────────
# Unit Tests for Scope Verification
# ─────────────────────────────────────────────

def test_scope_checker_same_origin() -> None:
    """Scope checker must accept same origin URLs and reject external domains."""
    seed = "https://example.com/"
    
    assert is_url_in_scope("https://example.com/about", seed) is True
    assert is_url_in_scope("http://example.com/contact", seed) is True
    assert is_url_in_scope("https://sub.example.com/page", seed) is False  # Subdomains disallowed by default
    assert is_url_in_scope("https://external.com/", seed) is False


def test_scope_checker_blocks_binaries() -> None:
    """Scope checker must reject media and archive binary paths."""
    seed = "https://example.com/"
    assert is_url_in_scope("https://example.com/docs/report.pdf", seed) is False
    assert is_url_in_scope("https://example.com/assets/logo.png", seed) is False
    assert is_url_in_scope("https://example.com/downloads/package.zip", seed) is False
    assert is_url_in_scope("https://example.com/assets/styles.css", seed) is True


# ─────────────────────────────────────────────
# Scanner Mock Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_endpoint_scanner_limits_and_scope() -> None:
    """Endpoint Scanner crawler must obey max depth, page count limits, and scope controls."""
    scanner = EndpointScanner()
    target_info = TargetInfo(original="https://crawler.com/", normalized="crawler.com", target_type=TARGET_TYPE_DOMAIN)
    
    # 1. Depth = 1 scan
    scanner_input = ScannerInput(
        target=target_info,
        configuration={
            "max_depth": 1,
            "max_pages": 10,
        }
    )

    # Mock server pages mapping
    pages = {
        "https://crawler.com/": (
            "<html><a href='/page1'>Page 1</a><a href='/page2'>Page 2</a></html>",
            "text/html"
        ),
        "https://crawler.com/page1": (
            "<html><a href='/page1/nested'>Page 1 Nested</a></html>",
            "text/html"
        ),
        "https://crawler.com/page2": (
            "<html><a href='https://external.com/leaving'>External</a></html>",
            "text/html"
        ),
        "https://crawler.com/page1/nested": (
            "<html></html>",
            "text/html"
        ),
    }

    async def mock_client_get(url, **kwargs):
        if url in pages:
            body, ctype = pages[url]
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": ctype},
                text=body,
                request=httpx.Request("GET", url),
            )
        return httpx.Response(status_code=404, request=httpx.Request("GET", url))

    # Test crawl with max_depth = 1
    with patch("httpx.AsyncClient.get", side_effect=mock_client_get):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 3
    urls = [r.url for r in result.results]
    # Root, /page1, and /page2 are crawled (depth 0 and 1)
    assert "https://crawler.com/" in urls
    assert "https://crawler.com/page1" in urls
    assert "https://crawler.com/page2" in urls
    # /page1/nested is depth 2 (ignored because max_depth=1)
    assert "https://crawler.com/page1/nested" not in urls
    # External url is out-of-scope (ignored)
    assert "https://external.com/leaving" not in urls


@pytest.mark.asyncio
async def test_endpoint_scanner_max_pages_limit() -> None:
    """Endpoint Scanner crawler must stop crawls immediately once max_pages limit is reached."""
    scanner = EndpointScanner()
    target_info = TargetInfo(original="https://crawler.com/", normalized="crawler.com", target_type=TARGET_TYPE_DOMAIN)
    
    # max_pages limit = 2
    scanner_input = ScannerInput(
        target=target_info,
        configuration={
            "max_depth": 3,
            "max_pages": 2,
        }
    )

    pages = {
        "https://crawler.com/": (
            "<html><a href='/page1'>Page 1</a><a href='/page2'>Page 2</a></html>",
            "text/html"
        ),
        "https://crawler.com/page1": (
            "<html><a href='/page3'>Page 3</a></html>",
            "text/html"
        ),
        "https://crawler.com/page2": (
            "<html></html>",
            "text/html"
        ),
    }

    async def mock_client_get(url, **kwargs):
        if url in pages:
            body, ctype = pages[url]
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": ctype},
                text=body,
                request=httpx.Request("GET", url),
            )
        return httpx.Response(status_code=404, request=httpx.Request("GET", url))

    with patch("httpx.AsyncClient.get", side_effect=mock_client_get):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    # Even though there are more links, crawl should stop exactly at 2 pages
    assert len(result.results) == 2
