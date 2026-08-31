"""
app/scanners/js/extractor.py

Analyzes JavaScript code content using AST/regex static analysis to extract REST paths,
absolute URLs, WebSockets, hostnames, request calls, template literals, source maps, and credentials.
Strips comments before extraction to prevent false positives in commented code.
"""

import re
from urllib.parse import urljoin, urlparse

from app.scanners.js.models import JsReference

# Match single-line comments (//...) avoiding http:// or https:// and multi-line comments (/* ... */)
_COMMENT_PATTERN = re.compile(r"(?<!:)//.*$|/\*[\s\S]*?\*/", re.MULTILINE)

# Match absolute URLs (http:// or https://)
_ABSOLUTE_URL_PATTERN = re.compile(r"['\"](https?://[a-zA-Z0-9_\-\.]+(?:\:[0-9]+)?(?:/[a-zA-Z0-9_\-\.\?&%=/#]*))['\"]", re.IGNORECASE)

# Match WebSockets (ws:// or wss://)
_WEBSOCKET_URL_PATTERN = re.compile(r"['\"](wss?://[a-zA-Z0-9_\-\.]+(?:\:[0-9]+)?(?:/[a-zA-Z0-9_\-\.\?&%=/#]*))['\"]", re.IGNORECASE)

# Match relative API endpoints and paths (/api/users, ./api/users, ../api/login) - requires multi-segment or /api/ prefix
_RELATIVE_PATH_PATTERN = re.compile(r"['\"]((?:/api/|\.{0,2}/[a-zA-Z0-9_\-\.]{1,}/)[a-zA-Z0-9_\-\.\?&%=/#]+)['\"]")

# Match request calls: fetch(), axios, $.ajax
_FETCH_PATTERN = re.compile(
    r"\bfetch\s*\(\s*['\"](.*?)['\"]\s*(?:,\s*\{\s*[^}]*?method\s*:\s*['\"]([A-Z]+)['\"])?",
    re.IGNORECASE,
)
_AXIOS_PATTERN = re.compile(
    r"\baxios\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*['\"](.*?)['\"]",
    re.IGNORECASE,
)
_AJAX_PATTERN = re.compile(
    r"\$\s*\.\s*(?:ajax|get|post)\s*\(\s*(?:['\"](.*?)['\"]|\{\s*[^}]*?url\s*:\s*['\"](.*?)['\"](?:\s*,\s*[^}]*?type\s*:\s*['\"]([A-Z]+)['\"])?)",
    re.IGNORECASE,
)

# Match template literals (e.g. `/api/${version}/users`)
_TEMPLATE_LITERAL_PATTERN = re.compile(r"`(/[^`\n]*?\$\{.*?\}[^`\n]*?)`")

# Match source map references
_SOURCEMAP_PATTERN = re.compile(r"(?://#|/\*#)\s*sourceMappingURL\s*=\s*([^\s\*]+)", re.IGNORECASE)

# Match API keys / secret tokens
_SECRET_PATTERN = re.compile(
    r"(?:api_key|apikey|secret|token|password|auth|jwt|session_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]",
    re.IGNORECASE,
)

# Match library version banners
_LIBRARY_BANNER_PATTERN = re.compile(
    r"\b(jQuery|React|Vue|Angular|Bootstrap|Lodash|Moment)\s*(?:v|version)?\s*([0-9]+\.[0-9]+\.?[0-9]*)\b",
    re.IGNORECASE,
)

# Extensions pointing to non-REST static media assets to filter out
_JUNK_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
)


def strip_comments(js_code: str) -> str:
    """
    Remove single-line and multi-line comments from JavaScript code.
    Preserves URL schemes (e.g. http://) while stripping real comments.
    """
    return _COMMENT_PATTERN.sub("", js_code)


def extract_js_references(
    js_code: str,
    source_file: str = "inline",
    origin_page_url: str | None = None,
) -> tuple[list[JsReference], list[str], list[str]]:
    """
    Statically analyze JavaScript content and extract references, endpoints, WebSockets,
    source maps, secrets, and library banners.
    
    Args:
        js_code: Raw JavaScript code string.
        source_file: Source URL or 'inline'.
        origin_page_url: Origin URL for relative path resolution.
        
    Returns:
        tuple[list[JsReference], list[str], list[str]]:
            - references: List of structured JsReference objects.
            - discovered_paths: List of path strings (backwards compatibility).
            - discovered_secrets: List of secret strings (backwards compatibility).
    """
    cleaned_code = strip_comments(js_code)
    references: list[JsReference] = []

    base_url = origin_page_url or (source_file if source_file.startswith(("http://", "https://")) else None)

    # 1. Extract Absolute URLs
    for match in _ABSOLUTE_URL_PATTERN.finditer(cleaned_code):
        abs_url = match.group(1).strip()
        parsed = urlparse(abs_url)
        cand_host = (parsed.hostname or "").lower()

        # Classify as external or local hostname reference
        origin_host = urlparse(base_url).hostname if base_url else None
        ref_type = "external_domain" if (origin_host and cand_host and cand_host != origin_host.lower()) else "absolute_url"

        references.append(
            JsReference(
                value=abs_url,
                type=ref_type,
                source_file=source_file,
                status="REFERENCED",
                confidence="high",
                resolution_base=base_url,
                resolved_reference=abs_url,
            )
        )

    # 2. Extract WebSockets
    for match in _WEBSOCKET_URL_PATTERN.finditer(cleaned_code):
        ws_url = match.group(1).strip()
        references.append(
            JsReference(
                value=ws_url,
                type="websocket_url",
                source_file=source_file,
                status="REFERENCED",
                confidence="high",
                resolution_base=base_url,
            )
        )

    # 3. Extract Request Patterns (fetch, axios, ajax)
    for match in _FETCH_PATTERN.finditer(cleaned_code):
        req_url = match.group(1).strip()
        req_method = match.group(2).upper() if match.group(2) else "GET"
        if req_url and not any(req_url.lower().endswith(ext) for ext in _JUNK_EXTENSIONS):
            resolved = urljoin(base_url, req_url) if base_url else None
            references.append(
                JsReference(
                    value=req_url,
                    type="api_endpoint",
                    source_file=source_file,
                    status="REFERENCED",
                    http_method=req_method,
                    confidence="high",
                    resolution_base=base_url,
                    resolved_reference=resolved,
                )
            )

    for match in _AXIOS_PATTERN.finditer(cleaned_code):
        req_method = match.group(1).upper()
        req_url = match.group(2).strip()
        if req_url and not any(req_url.lower().endswith(ext) for ext in _JUNK_EXTENSIONS):
            resolved = urljoin(base_url, req_url) if base_url else None
            references.append(
                JsReference(
                    value=req_url,
                    type="api_endpoint",
                    source_file=source_file,
                    status="REFERENCED",
                    http_method=req_method,
                    confidence="high",
                    resolution_base=base_url,
                    resolved_reference=resolved,
                )
            )

    for match in _AJAX_PATTERN.finditer(cleaned_code):
        req_url = (match.group(1) or match.group(2) or "").strip()
        req_method = match.group(3).upper() if match.group(3) else "GET"
        if req_url and not any(req_url.lower().endswith(ext) for ext in _JUNK_EXTENSIONS):
            resolved = urljoin(base_url, req_url) if base_url else None
            references.append(
                JsReference(
                    value=req_url,
                    type="api_endpoint",
                    source_file=source_file,
                    status="REFERENCED",
                    http_method=req_method,
                    confidence="high",
                    resolution_base=base_url,
                    resolved_reference=resolved,
                )
            )

    # 4. Extract Relative REST Paths
    for match in _RELATIVE_PATH_PATTERN.finditer(cleaned_code):
        rel_path = match.group(1).strip()
        if rel_path and not rel_path.startswith("//") and not any(rel_path.lower().endswith(ext) for ext in _JUNK_EXTENSIONS):
            resolved = urljoin(base_url, rel_path) if base_url else None
            references.append(
                JsReference(
                    value=rel_path,
                    type="relative_path",
                    source_file=source_file,
                    status="REFERENCED",
                    confidence="medium",
                    resolution_base=base_url,
                    resolved_reference=resolved,
                )
            )

    # 5. Extract Template Literals
    for match in _TEMPLATE_LITERAL_PATTERN.finditer(cleaned_code):
        tmpl_val = match.group(1).strip()
        references.append(
            JsReference(
                value=tmpl_val,
                type="api_endpoint",
                source_file=source_file,
                status="partially_resolved",
                confidence="medium",
                resolution_base=base_url,
            )
        )

    # 6. Extract Source Maps (from original code before comment stripping)
    for match in _SOURCEMAP_PATTERN.finditer(js_code):
        sm_val = match.group(1).strip()
        resolved_sm = urljoin(base_url, sm_val) if base_url else None
        references.append(
            JsReference(
                value=sm_val,
                type="source_map",
                source_file=source_file,
                status="REFERENCED",
                confidence="high",
                resolution_base=base_url,
                resolved_reference=resolved_sm,
            )
        )

    # 7. Extract Secrets
    for match in _SECRET_PATTERN.finditer(cleaned_code):
        sec_val = match.group(1).strip()
        references.append(
            JsReference(
                value=sec_val,
                type="secret",
                source_file=source_file,
                status="REFERENCED",
                confidence="medium",
            )
        )

    # 8. Extract Library Banners
    for match in _LIBRARY_BANNER_PATTERN.finditer(js_code):  # check original comments too for banners
        lib_name = match.group(1).strip()
        lib_ver = match.group(2).strip()
        references.append(
            JsReference(
                value=f"{lib_name} v{lib_ver}",
                type="library_identifier",
                source_file=source_file,
                status="REFERENCED",
                confidence="high",
            )
        )

    # Deduplicate references by (value, type, http_method)
    seen = set()
    deduped_refs: list[JsReference] = []
    for ref in references:
        key = (ref.value, ref.type, ref.http_method)
        if key not in seen:
            seen.add(key)
            deduped_refs.append(ref)

    # Backwards compatibility lists
    discovered_paths = list(
        dict.fromkeys(r.value for r in deduped_refs if r.type in ("relative_path", "api_endpoint", "absolute_url"))
    )
    discovered_secrets = list(
        dict.fromkeys(r.value for r in deduped_refs if r.type == "secret")
    )

    return deduped_refs, discovered_paths, discovered_secrets


def extract_endpoints_and_secrets(js_code: str) -> tuple[list[str], list[str]]:
    """Backwards compatibility function returning paths and secrets."""
    _, paths, secrets = extract_js_references(js_code)
    return paths, secrets
