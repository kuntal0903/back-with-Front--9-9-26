"""
tests/test_tech_scanner_accuracy.py

Comprehensive test suite for Technology Detection multi-signal evidence engine,
validating explicit headers, HTML meta generator, script srcs, stylesheet hrefs, asset paths,
cookies, DOM structures, deterministic confidence engine, version extraction precision,
negative indicators, and false-positive controls.
"""

import pytest
from app.scanners.tech.fingerprinter import fingerprint_response


def test_explicit_server_header_nginx() -> None:
    """Explicit Server header returns tech match with version extracted."""
    headers = {"server": "nginx/1.24.0"}
    detected = fingerprint_response(headers, "<html></html>", [])

    nginx_matches = [t for t in detected if t.name == "nginx"]
    assert len(nginx_matches) == 1
    tech = nginx_matches[0]
    assert tech.category == "web_server"
    assert tech.version == "1.24.0"
    assert tech.confidence == "medium"
    assert any(e.type == "http_header" and e.source == "header:server" for e in tech.evidence)


def test_explicit_framework_header_laravel() -> None:
    """Framework X-Powered-By header matching."""
    headers = {"x-powered-by": "Laravel"}
    detected = fingerprint_response(headers, "<html></html>", [])

    matches = [t for t in detected if t.name == "Laravel"]
    assert len(matches) == 1
    assert matches[0].category in ("framework", "backend_framework")
    assert matches[0].confidence == "medium"


def test_generator_metadata_wordpress() -> None:
    """HTML generator meta tag match produces high confidence and version."""
    html = '<meta name="generator" content="WordPress 6.2.2" />'
    detected = fingerprint_response({}, html, [])

    wp = next((t for t in detected if t.name == "WordPress"), None)
    assert wp is not None
    assert wp.category == "cms"
    assert wp.version == "6.2.2"
    assert wp.confidence == "high"
    assert "meta_tag" in wp.detection_methods


def test_script_src_fingerprint_react_vue_angular() -> None:
    """Script src fingerprinting identifies React, Vue, Angular."""
    html = """
    <html>
      <head>
        <script src="/static/js/react.production.min.js"></script>
        <script src="/static/js/vue.global.prod.js"></script>
        <script src="/static/js/angular.min.js"></script>
      </head>
    </html>
    """
    detected = fingerprint_response({}, html, [])

    names = [t.name for t in detected]
    assert "React" in names
    assert "Vue.js" in names
    assert "Angular" in names


def test_stylesheet_asset_fingerprint_bootstrap_elementor() -> None:
    """Stylesheet href and static asset paths match technology signatures."""
    html = """
    <html>
      <head>
        <link rel="stylesheet" href="/assets/css/bootstrap.min.css" />
        <link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css" />
      </head>
    </html>
    """
    detected = fingerprint_response({}, html, [])

    names = [t.name for t in detected]
    assert "Bootstrap" in names
    assert "Elementor" in names


def test_cookie_fingerprint_cloudflare_drupal() -> None:
    """Cookie names match technology signatures."""
    cookies = ["__cf_bm", "SESSa1b2c3d4e5f678901234567890abcdef"]
    detected = fingerprint_response({}, "<html></html>", cookies)

    names = [t.name for t in detected]
    assert "Cloudflare" in names
    assert "Drupal" in names


def test_html_dom_fingerprint_nextjs_nuxt() -> None:
    """HTML body DOM attributes match Next.js and Nuxt.js."""
    html = '<html><body><div id="__NEXT_DATA__"></div></body></html>'
    detected = fingerprint_response({}, html, [])

    names = [t.name for t in detected]
    assert "Next.js" in names
    next_tech = next(t for t in detected if t.name == "Next.js")
    assert next_tech.confidence == "high"


def test_multiple_evidence_sources_boosts_confidence() -> None:
    """Multiple independent evidence sources boost confidence rating to high."""
    headers = {"x-powered-by": "WordPress"}
    html = """
    <html>
      <head>
        <link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css" />
      </head>
      <body>
        <script src="/wp-includes/js/wp-embed.min.js"></script>
      </body>
    </html>
    """
    cookies = ["wordpress_logged_in_abc"]

    detected = fingerprint_response(headers, html, cookies)
    wp = next(t for t in detected if t.name == "WordPress")

    assert wp.confidence == "high"
    assert len(wp.detection_methods) >= 3  # http_header, stylesheet_href, script_src, cookie_name
    assert "http_header" in wp.detection_methods
    assert "cookie_name" in wp.detection_methods


def test_weak_evidence_returns_lower_confidence() -> None:
    """Single header indicator returns medium/low confidence without overstating certainty."""
    headers = {"server": "Apache/2.4.52"}
    detected = fingerprint_response(headers, "<html></html>", [])

    apache = next(t for t in detected if t.name == "Apache")
    assert apache.confidence == "medium"
    assert apache.version == "2.4.52"


def test_missing_version_returns_none() -> None:
    """If version cannot be established directly, version is strictly None."""
    headers = {"server": "nginx"}
    detected = fingerprint_response(headers, "<html></html>", [])

    nginx = next(t for t in detected if t.name == "nginx")
    assert nginx.version is None


def test_no_evidence_returns_empty() -> None:
    """Target returning generic response with no match returns empty technology list."""
    detected = fingerprint_response({"content-type": "text/html"}, "<html>Hello World</html>", [])
    assert len(detected) == 0


def test_duplicate_evidence_deduplication() -> None:
    """Duplicate evidence indicators are deduplicated cleanly."""
    html = """
    <html>
      <head>
        <meta name="generator" content="WordPress 6.0" />
        <meta name="generator" content="WordPress 6.0" />
      </head>
    </html>
    """
    detected = fingerprint_response({}, html, [])

    wp = next(t for t in detected if t.name == "WordPress")
    # Evidence objects should be deduplicated
    unique_ev = set((e.type, e.source, e.value) for e in wp.evidence)
    assert len(wp.evidence) == len(unique_ev)
