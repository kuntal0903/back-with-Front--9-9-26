"""
app/scanners/js/parser.py

Scrapes and extracts inline JS code and external source script URLs from HTML pages.
Parses module scripts, preload links, and filters out non-JavaScript blocks.
"""

import re
from urllib.parse import urljoin, urlparse

# Match HTML <script> tag structure: captures attributes and inner body content
_SCRIPT_TAG_PATTERN = re.compile(r"<script([^>]*?)>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_LINK_PRELOAD_PATTERN = re.compile(r"<link\s+[^>]*?href\s*=\s*[\"'](.*?)[\"'][^>]*?>", re.IGNORECASE)

# Patterns to inspect attributes inside a matched script tag
_SRC_ATTR_PATTERN = re.compile(r"\bsrc\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_TYPE_ATTR_PATTERN = re.compile(r"\btype\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_REL_ATTR_PATTERN = re.compile(r"\brel\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_AS_ATTR_PATTERN = re.compile(r"\bas\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)


def extract_script_sources(base_url: str, html_body: str) -> tuple[list[str], list[str]]:
    """
    Locate inline JS blocks and extract external absolute script URLs from the HTML.
    
    Filters out non-JS script elements (like type="text/template" or type="application/json").
    Parses module scripts and preloaded script links.
    
    Args:
        base_url: The originating page URL.
        html_body: Raw HTML content string.
        
    Returns:
        tuple[list[str], list[str]]:
            - list[str]: Inline JS content blocks.
            - list[str]: Absolute normalized URLs of external scripts.
    """
    inline_blocks = []
    external_urls = []

    # 1. Find all <script> elements
    matches = _SCRIPT_TAG_PATTERN.finditer(html_body)

    for match in matches:
        attrs = match.group(1).strip()
        body = match.group(2).strip()

        # Parse type attribute if present
        type_match = _TYPE_ATTR_PATTERN.search(attrs)
        is_valid_js = True

        if type_match:
            type_val = type_match.group(1).lower().strip()
            # Valid types: text/javascript, application/javascript, module, text/ecmascript, etc.
            if "javascript" not in type_val and "ecmascript" not in type_val and type_val != "module":
                is_valid_js = False

        if not is_valid_js:
            continue

        # Parse src attribute to check if it's an external file reference
        src_match = _SRC_ATTR_PATTERN.search(attrs)

        if src_match:
            src_url = src_match.group(1).strip()
            if src_url:
                try:
                    absolute = urljoin(base_url, src_url)
                    parsed = urlparse(absolute)
                    if parsed.scheme in ("http", "https") and parsed.netloc:
                        cleaned_url = parsed._replace(fragment="").geturl()
                        external_urls.append(cleaned_url)
                except Exception:
                    pass
        else:
            # Inline script block
            if body:
                inline_blocks.append(body)

    # 2. Parse <link rel="modulepreload" ...> or <link rel="preload" as="script" ...>
    for link_match in _LINK_PRELOAD_PATTERN.finditer(html_body):
        tag_str = link_match.group(0)
        href_val = link_match.group(1).strip()

        rel_match = _REL_ATTR_PATTERN.search(tag_str)
        rel_val = rel_match.group(1).lower().strip() if rel_match else ""

        as_match = _AS_ATTR_PATTERN.search(tag_str)
        as_val = as_match.group(1).lower().strip() if as_match else ""

        if rel_val == "modulepreload" or (rel_val == "preload" and as_val == "script"):
            if href_val:
                try:
                    absolute = urljoin(base_url, href_val)
                    parsed = urlparse(absolute)
                    if parsed.scheme in ("http", "https") and parsed.netloc:
                        cleaned_url = parsed._replace(fragment="").geturl()
                        external_urls.append(cleaned_url)
                except Exception:
                    pass

    # Deduplicate external URLs
    seen = set()
    deduped_externals = []
    for url in external_urls:
        if url not in seen:
            seen.add(url)
            deduped_externals.append(url)

    return inline_blocks, deduped_externals
