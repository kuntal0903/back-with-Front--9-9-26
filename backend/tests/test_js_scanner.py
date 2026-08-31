"""
tests/test_js_scanner.py

Tests for the JavaScript Discovery Scanner, validating parser scripts extraction,
inner REST paths matching, secret credentials scanning, and mock connection pipelines.
"""

import httpx
import pytest
from unittest.mock import AsyncMock, patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.js.extractor import extract_endpoints_and_secrets
from app.scanners.js.parser import extract_script_sources
from app.scanners.js.scanner import JsScanner


# ─────────────────────────────────────────────
# Unit Tests for Script Tag Parser
# ─────────────────────────────────────────────

def test_script_tag_parser_inline_and_src() -> None:
    """Parser must capture inline JS code block contents and extract external source links."""
    html = """
    <html>
      <head>
        <script>
          var apiKey = "inline-token-abc";
          console.log("Hello Inline");
        </script>
        <script src="/assets/app.js"></script>
        <script type="text/javascript" src="https://cdn.example.com/jquery.min.js"></script>
        <!-- ignored non-src tag -->
        <script type="text/template"><div>template</div></script>
      </head>
    </html>
    """
    inline, externals = extract_script_sources("https://example.com/", html)
    
    # Verify inline blocks
    assert len(inline) == 1
    assert "var apiKey =" in inline[0]
    
    # Verify external src URLs resolved
    assert len(externals) == 2
    assert "https://example.com/assets/app.js" in externals
    assert "https://cdn.example.com/jquery.min.js" in externals


# ─────────────────────────────────────────────
# Unit Tests for JS Code Extractor
# ─────────────────────────────────────────────

def test_js_extractor_endpoints() -> None:
    """Extractor must parse relative paths and ignore static image/media assets."""
    js_code = """
    fetch("/api/v1/users").then(r => r.json());
    var page = "/dashboard/overview?user=1";
    var asset = "/images/logo.png"; // ignored junk extension
    var style = "/assets/styles.css"; // ignored junk extension
    var short = "/ok"; // generic short string ignored
    """
    paths, _ = extract_endpoints_and_secrets(js_code)
    
    assert len(paths) == 2
    assert "/api/v1/users" in paths
    assert "/dashboard/overview?user=1" in paths
    assert "/images/logo.png" not in paths
    assert "/assets/styles.css" not in paths


def test_js_extractor_secrets() -> None:
    """Extractor must identify configuration keys, tokens, and credentials patterns."""
    js_code = """
    var clientSecret = "super-secret-password-12345";
    const apiKey = "AIzaSyD_abc123XYZ-9876543210";
    let token = "jwt.header.payload.signature";
    """
    _, secrets = extract_endpoints_and_secrets(js_code)
    
    assert len(secrets) == 3
    assert "super-secret-password-12345" in secrets
    assert "AIzaSyD_abc123XYZ-9876543210" in secrets
    assert "jwt.header.payload.signature" in secrets


# ─────────────────────────────────────────────
# Scanner Mock Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_js_scanner_success_flow() -> None:
    """JS Scanner must query seeds, fetch external script assets, and parse findings."""
    scanner = JsScanner()
    target_info = TargetInfo(original="https://example.com/", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    # Web pages mappings
    pages = {
        "https://example.com/": (
            "<html>"
            "<script>var secret = 'inline-secret-token-123456';</script>"
            "<script src='/assets/main.js'></script>"
            "</html>",
            "text/html"
        ),
        "https://example.com/assets/main.js": (
            "var api_endpoint = '/api/v2/checkout';\n"
            "var other_endpoint = '/api/v2/items';",
            "application/javascript"
        )
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
    assert len(result.results) == 1
    
    rec = result.results[0]
    assert rec.origin_url == "https://example.com/"
    assert len(rec.scripts) == 2

    # Inline script checks
    inline_script = [s for s in rec.scripts if s.script_url == "inline"][0]
    assert "inline-secret-token-123456" in inline_script.discovered_secrets

    # External script checks
    ext_script = [s for s in rec.scripts if s.script_url == "https://example.com/assets/main.js"][0]
    assert "/api/v2/checkout" in ext_script.discovered_paths
    assert "/api/v2/items" in ext_script.discovered_paths

    # Evidence lists checks
    # Inline script (1) + main.js (1) = 2
    assert len(result.evidence) == 2
    inline_ev = [e for e in result.evidence if e.raw_evidence["script_url"] == "inline"][0]
    ext_ev = [e for e in result.evidence if e.raw_evidence["script_url"] == "https://example.com/assets/main.js"][0]
    assert inline_ev.raw_evidence["secrets_count"] == 1
    assert ext_ev.raw_evidence["paths_count"] == 2
