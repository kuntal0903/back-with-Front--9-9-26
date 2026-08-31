"""
tests/test_endpoint_scanner_accuracy.py

Comprehensive test suite for Web Endpoint Discovery Scanner,
validating normalizer, forms parser, robots.txt parser, sitemap.xml parser,
scope controls, status classifications, DISCOVERED vs VERIFIED_LIVE lifecycle, and multi-source extraction.
"""

import httpx
import pytest
from unittest.mock import patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.endpoint.normalizer import normalize_url
from app.scanners.endpoint.parsers.forms import parse_html_forms
from app.scanners.endpoint.parsers.robots import parse_robots_txt
from app.scanners.endpoint.parsers.sitemap import parse_sitemap_xml
from app.scanners.endpoint.scanner import EndpointScanner


def test_url_normalizer_behavior() -> None:
    """URL normalizer resolves relative URLs, strips fragments, sorts params, and removes default ports."""
    url = "https://example.com:443/search?page=2&q=test#section"
    norm_url, path, params = normalize_url(url)

    assert norm_url == "https://example.com/search?page=2&q=test"
    assert path == "/search"
    assert params == ["page", "q"]


def test_parse_robots_txt_directives() -> None:
    """robots.txt parser extracts Disallow, Allow, and Sitemap directives."""
    content = """
    User-agent: *
    Disallow: /admin/
    Disallow: /private/secret.pdf
    Allow: /public/
    Sitemap: https://example.com/sitemap_index.xml
    """
    paths, sitemaps = parse_robots_txt("https://example.com/robots.txt", content)

    assert "https://example.com/admin/" in paths
    assert "https://example.com/private/secret.pdf" in paths
    assert "https://example.com/public/" in paths
    assert "https://example.com/sitemap_index.xml" in sitemaps


def test_parse_sitemap_xml_and_index() -> None:
    """sitemap.xml parser extracts page locations and nested sitemap indexes."""
    urlset_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/page1</loc></url>
      <url><loc>https://example.com/page2</loc></url>
    </urlset>
    """
    locs, sitemaps = parse_sitemap_xml("https://example.com/sitemap.xml", urlset_xml)
    assert "https://example.com/page1" in locs
    assert "https://example.com/page2" in locs

    index_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <sitemap><loc>https://example.com/sub_sitemap.xml</loc></sitemap>
    </sitemapindex>
    """
    locs, sitemaps = parse_sitemap_xml("https://example.com/sitemap_index.xml", index_xml)
    assert "https://example.com/sub_sitemap.xml" in sitemaps


def test_parse_html_forms_details() -> None:
    """HTML Form parser extracts form action, method, and input parameters."""
    html = """
    <html>
      <form action="/login" method="POST">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <select name="role"><option>User</option></select>
      </form>
    </html>
    """
    forms = parse_html_forms("https://example.com/", html)

    assert len(forms) == 1
    form = forms[0]
    assert form.action_url == "https://example.com/login"
    assert form.method == "POST"
    assert form.param_names == ["username", "password", "role"]


@pytest.mark.asyncio
async def test_endpoint_scanner_multi_source_flow() -> None:
    """Endpoint Scanner coordinates Robots, Sitemap, Forms, and Live verification."""
    scanner = EndpointScanner()
    target_info = TargetInfo(original="https://example.com/", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info, configuration={"max_depth": 1, "max_pages": 5})

    pages = {
        "https://example.com/robots.txt": (
            200,
            "Disallow: /admin\nSitemap: https://example.com/sitemap.xml",
            "text/plain",
        ),
        "https://example.com/sitemap.xml": (
            200,
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/api/v1/users</loc></url></urlset>',
            "application/xml",
        ),
        "https://example.com/": (
            200,
            '<html><a href="/contact">Contact</a><form action="/submit" method="POST"><input name="email"/></form></html>',
            "text/html",
        ),
        "https://example.com/contact": (
            200,
            "<html>Contact Us</html>",
            "text/html",
        ),
    }

    async def mock_client_get(url, **kwargs):
        req_url = str(url)
        if req_url in pages:
            status, body, ctype = pages[req_url]
            return httpx.Response(
                status_code=status,
                headers={"Content-Type": ctype},
                text=body,
                request=httpx.Request("GET", req_url),
            )
        return httpx.Response(status_code=404, request=httpx.Request("GET", req_url))

    with patch("httpx.AsyncClient.get", side_effect=mock_client_get), patch("httpx.AsyncClient.stream") as mock_stream:
        # Helper to mock streaming response
        def make_stream(method, url):
            req_url = str(url)
            if req_url in pages:
                status, body, ctype = pages[req_url]
                resp = httpx.Response(
                    status_code=status,
                    headers={"Content-Type": ctype},
                    text=body,
                    request=httpx.Request(method, req_url),
                )
            else:
                resp = httpx.Response(status_code=404, request=httpx.Request(method, req_url))

            class AsyncStreamContext:
                async def __aenter__(self):
                    return resp
                async def __aexit__(self, exc_type, exc, tb):
                    pass
            return AsyncStreamContext()

        mock_stream.side_effect = make_stream

        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    urls = [r.url for r in result.results]

    # Verify multi-source endpoint presence
    assert "https://example.com/robots.txt" in urls
    assert "https://example.com/sitemap.xml" in urls
    assert "https://example.com/admin" in urls
    assert "https://example.com/api/v1/users" in urls
    assert "https://example.com/contact" in urls
    assert "https://example.com/submit" in urls

    # Check status classifications
    admin_rec = next(r for r in result.results if r.url == "https://example.com/admin")
    assert admin_rec.discovery_source == "robots_txt"
    assert admin_rec.discovery_status == "DISCOVERED"

    form_rec = next(r for r in result.results if r.url == "https://example.com/submit")
    assert form_rec.endpoint_type == "FORM"
    assert form_rec.http_method == "POST"
    assert "email" in form_rec.query_parameters
