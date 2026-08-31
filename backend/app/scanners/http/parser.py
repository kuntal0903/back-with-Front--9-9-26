"""
app/scanners/http/parser.py

Parses HTML response payloads, headers, cookies, and server metadata.
Uses lightweight regular expressions and header structures.
"""

import html
import re
from typing import Any

# Match title tag and capture content (handles multiline titles)
_TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Match individual meta tags
_META_PATTERN = re.compile(r"<meta\s+([^>]*?)>", re.IGNORECASE)

_NAME_ATTR = re.compile(r"name\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_PROPERTY_ATTR = re.compile(r"property\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_CONTENT_ATTR = re.compile(r"content\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)


def parse_page_title(html_content: str) -> str | None:
    """
    Extract the value inside the HTML <title> tag.
    Returns None if absent. Does NOT guess title.
    """
    if not html_content:
        return None
    match = _TITLE_PATTERN.search(html_content)
    if not match:
        return None
    
    raw_title = match.group(1).strip()
    if not raw_title:
        return None
    cleaned_title = re.sub(r"\s+", " ", raw_title)
    return html.unescape(cleaned_title)


def parse_page_metadata(html_content: str) -> dict[str, str]:
    """
    Extract common HTML metadata fields from <meta> tags.
    """
    metadata = {}
    if not html_content:
        return metadata

    meta_tags = _META_PATTERN.findall(html_content)
    for tag_content in meta_tags:
        content_match = _CONTENT_ATTR.search(tag_content)
        if not content_match:
            continue
        
        content_val = html.unescape(content_match.group(1).strip())
        name_match = _NAME_ATTR.search(tag_content)
        if name_match:
            key = name_match.group(1).strip().lower()
            if key in ("description", "keywords", "generator", "author", "robots"):
                metadata[key] = content_val
                continue
                
        prop_match = _PROPERTY_ATTR.search(tag_content)
        if prop_match:
            key = prop_match.group(1).strip().lower()
            if key in ("og:title", "og:description", "og:site_name", "og:type"):
                metadata[key] = content_val

    return metadata


def parse_server_header(server_header: str | None) -> tuple[str | None, str | None]:
    """
    Extract (server_product, server_version) from explicit Server header value.
    Does NOT infer version if not explicitly provided.
    """
    if not server_header or not server_header.strip():
        return None, None

    cleaned = server_header.strip()
    sh_lower = cleaned.lower()

    if "nginx" in sh_lower:
        product = "nginx"
        m = re.search(r"nginx/([0-9\.]+)", cleaned, re.IGNORECASE)
        version = m.group(1) if m else None
        return product, version

    elif "apache" in sh_lower:
        product = "Apache"
        m = re.search(r"apache/([0-9\.]+)", cleaned, re.IGNORECASE)
        version = m.group(1) if m else None
        return product, version

    elif "iis" in sh_lower:
        product = "Microsoft-IIS"
        m = re.search(r"microsoft-iis/([0-9\.]+)", cleaned, re.IGNORECASE)
        version = m.group(1) if m else None
        return product, version

    # Generic header e.g. "gws" or "LiteSpeed/5.0"
    parts = cleaned.split("/")
    product = parts[0].strip()
    version = None
    if len(parts) > 1:
        v_candidate = parts[1].split()[0].strip()
        if v_candidate and any(char.isdigit() for char in v_candidate):
            version = v_candidate

    return product, version


def parse_security_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Extract observed security headers from lower-case headers mapping.
    """
    sec_keys = {
        "strict-transport-security": "Strict-Transport-Security",
        "content-security-policy": "Content-Security-Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    found = {}
    for h_lower, val in headers.items():
        if h_lower in sec_keys:
            found[sec_keys[h_lower]] = val
    return found


def parse_cookies_metadata(set_cookie_headers: list[str]) -> list[dict[str, Any]]:
    """
    Parse metadata attributes from Set-Cookie header lines without storing sensitive secret values.
    """
    cookie_list = []
    for header in set_cookie_headers:
        parts = header.split(";")
        if not parts:
            continue
        first_part = parts[0].strip()
        if "=" not in first_part:
            continue
        cookie_name = first_part.split("=", 1)[0].strip()

        attributes = {"name": cookie_name}
        for attr in parts[1:]:
            attr_clean = attr.strip().lower()
            if "=" in attr_clean:
                k, v = attr_clean.split("=", 1)
                if k in ("domain", "path", "expires", "max-age", "samesite"):
                    attributes[k] = v
            else:
                if attr_clean in ("secure", "httponly"):
                    attributes[attr_clean] = True

        cookie_list.append(attributes)
    return cookie_list
