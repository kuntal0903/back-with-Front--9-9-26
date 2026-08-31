"""
app/scanners/endpoint/extractor.py

Scrapes and extracts resource URLs, links, forms, scripts, and stylesheets from HTML pages.
"""

import re

from app.scanners.endpoint.normalizer import normalize_url

# Regex patterns matching resource attributes
_HREF_PATTERN = re.compile(r"<a\s+[^>]*?href\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_LINK_TAG_PATTERN = re.compile(r"<link\s+[^>]*?href\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_SCRIPT_TAG_PATTERN = re.compile(r"<script\s+[^>]*?src\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_RESOURCE_TAG_PATTERN = re.compile(r"<(?:img|iframe|source|video|audio)\s+[^>]*?src\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)

_IGNORE_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "#")


class ExtractedResource:
    def __init__(self, raw_url: str, normalized_url: str, path: str, resource_type: str, discovery_source: str, query_params: list[str]):
        self.raw_url = raw_url
        self.normalized_url = normalized_url
        self.path = path
        self.resource_type = resource_type
        self.discovery_source = discovery_source
        self.query_params = query_params


def extract_html_resources(base_url: str, html_body: str) -> list[ExtractedResource]:
    """
    Scrape all link, resource, form, and script endpoints from HTML body.
    
    Args:
        base_url: The absolute source page URL.
        html_body: HTML content string.
        
    Returns:
        list[ExtractedResource]: Collection of extracted resources.
    """
    resources: list[ExtractedResource] = []

    def _process(raw_attr: str, rtype: str, dsource: str) -> None:
        href = raw_attr.strip()
        if not href or href.lower().startswith(_IGNORE_SCHEMES):
            return

        try:
            norm_url, path, params = normalize_url(href, base_url)
            # Infer API endpoint type if path indicates REST/API structure
            final_type = rtype
            if rtype == "PAGE" and any(marker in path.lower() for marker in ("/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi")):
                final_type = "API"

            resources.append(
                ExtractedResource(
                    raw_url=href,
                    normalized_url=norm_url,
                    path=path,
                    resource_type=final_type,
                    discovery_source=dsource,
                    query_params=params,
                )
            )
        except Exception:
            pass

    # 1. Parse anchors <a href>
    for m in _HREF_PATTERN.finditer(html_body):
        _process(m.group(1), "PAGE", "html_anchor")

    # 2. Parse head/link tags <link href>
    for m in _LINK_TAG_PATTERN.finditer(html_body):
        _process(m.group(1), "STYLESHEET", "html_link")

    # 3. Parse script tags <script src>
    for m in _SCRIPT_TAG_PATTERN.finditer(html_body):
        _process(m.group(1), "SCRIPT", "script_tag")

    # 4. Parse image/media tags <img/iframe/video src>
    for m in _RESOURCE_TAG_PATTERN.finditer(html_body):
        _process(m.group(1), "MEDIA", "resource_tag")

    # Deduplicate extracted resources by normalized_url
    seen = set()
    deduped: list[ExtractedResource] = []
    for r in resources:
        if r.normalized_url not in seen:
            seen.add(r.normalized_url)
            deduped.append(r)

    return deduped


def extract_html_links(base_url: str, html_body: str) -> list[str]:
    """Backwards compatible link extractor returning list of URLs."""
    res = extract_html_resources(base_url, html_body)
    return [r.normalized_url for r in res if r.resource_type in ("PAGE", "API")]
