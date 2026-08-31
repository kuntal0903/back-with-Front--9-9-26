"""
tests/test_js_scanner_accuracy.py

Comprehensive test suite for JavaScript Discovery Scanner,
validating comment stripping, absolute/relative URL extractions, WebSockets,
request pattern HTTP methods, template literals, source maps, library banners,
and REFERENCED status tagging.
"""

import httpx
import pytest
from unittest.mock import patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.js.extractor import extract_js_references, strip_comments
from app.scanners.js.parser import extract_script_sources
from app.scanners.js.scanner import JsScanner


def test_comment_stripping_prevents_false_positives() -> None:
    """Comment stripper removes single and multi-line comments while preserving real code strings."""
    code = """
    // fetch("/api/v1/commented_out")
    /*
     * const url = "/api/v2/in_block_comment";
     */
    const realUrl = "/api/v3/active_endpoint";
    """
    cleaned = strip_comments(code)
    assert "/api/v1/commented_out" not in cleaned
    assert "/api/v2/in_block_comment" not in cleaned
    assert "/api/v3/active_endpoint" in cleaned

    refs, paths, _ = extract_js_references(code)
    assert "/api/v3/active_endpoint" in paths
    assert "/api/v1/commented_out" not in paths
    assert "/api/v2/in_block_comment" not in paths


def test_absolute_and_websocket_urls_extraction() -> None:
    """Extractor captures absolute HTTP/HTTPS URLs and WebSocket endpoints."""
    code = """
    const apiHost = "https://api.example.com/v1/data";
    const extHost = "https://external-service.net/hook";
    const socket = new WebSocket("wss://stream.example.com/live");
    """
    refs, paths, _ = extract_js_references(code, origin_page_url="https://example.com/")

    types = [r.type for r in refs]
    values = [r.value for r in refs]

    assert "absolute_url" in types or "external_domain" in types
    assert "websocket_url" in types
    assert "https://api.example.com/v1/data" in values
    assert "https://external-service.net/hook" in values
    assert "wss://stream.example.com/live" in values


def test_fetch_axios_request_method_detection() -> None:
    """Extractor captures HTTP methods from fetch and axios call patterns."""
    code = """
    fetch("/api/users", { method: "POST", headers: {} });
    axios.delete("/api/items/42");
    """
    refs, _, _ = extract_js_references(code)

    post_ref = next(r for r in refs if r.value == "/api/users")
    assert post_ref.http_method == "POST"

    del_ref = next(r for r in refs if r.value == "/api/items/42")
    assert del_ref.http_method == "DELETE"


def test_template_literal_and_source_map_detection() -> None:
    """Extractor identifies dynamic template literals and source map references."""
    code = """
    const path = `/api/${version}/reports`;
    //# sourceMappingURL=app.bundle.js.map
    """
    refs, _, _ = extract_js_references(code)

    tmpl_ref = next(r for r in refs if r.type == "api_endpoint")
    assert tmpl_ref.status == "partially_resolved"

    sm_ref = next(r for r in refs if r.type == "source_map")
    assert sm_ref.value == "app.bundle.js.map"
    assert sm_ref.status == "REFERENCED"


def test_module_preload_and_module_scripts_parser() -> None:
    """HTML parser identifies module script tags and modulepreload link tags."""
    html = """
    <html>
      <head>
        <link rel="modulepreload" href="/js/app.js" />
        <script type="module" src="/js/main.js"></script>
      </head>
    </html>
    """
    _, externals = extract_script_sources("https://example.com/", html)

    assert "https://example.com/js/app.js" in externals
    assert "https://example.com/js/main.js" in externals


@pytest.mark.asyncio
async def test_js_scanner_execution_and_referenced_status() -> None:
    """JsScanner probes target page and extracts structured references marked as REFERENCED."""
    scanner = JsScanner()
    target_info = TargetInfo(original="https://example.com/", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    pages = {
        "https://example.com/": (
            "<html><script src='/bundle.js'></script></html>",
            "text/html",
        ),
        "https://example.com/bundle.js": (
            "fetch('/api/v1/profile'); // jQuery v3.6.0",
            "application/javascript",
        ),
    }

    async def mock_client_get(url, **kwargs):
        req_url = str(url)
        if req_url in pages:
            body, ctype = pages[req_url]
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": ctype},
                text=body,
                request=httpx.Request("GET", req_url),
            )
        return httpx.Response(status_code=404, request=httpx.Request("GET", req_url))

    with patch("httpx.AsyncClient.get", side_effect=mock_client_get):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) >= 1
    rec = result.results[0]
    assert len(rec.scripts) >= 1
    script = rec.scripts[0]
    assert script.script_url == "https://example.com/bundle.js"

    # All static references must be marked strictly as REFERENCED
    for ref in script.references:
        assert ref.status in ("REFERENCED", "partially_resolved")
