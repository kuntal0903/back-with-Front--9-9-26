"""
app/scanners/endpoint/normalizer.py

URL normalization engine for endpoint identity tracking and deduplication.
Handles relative joins, fragment stripping, port default normalization,
character encoding/decoding, and clean query parameter sorting.
"""

from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


def normalize_url(url: str, base_url: str | None = None) -> tuple[str, str, list[str]]:
    """
    Normalize a raw candidate URL relative to base_url.
    
    Args:
        url: The candidate URL string.
        base_url: Optional base URL for resolving relative links.
        
    Returns:
        tuple[str, str, list[str]]:
            - normalized_url: Normalized absolute identity URL (fragment stripped).
            - path: Standardized path segment.
            - parameters: Sorted list of unique parameter keys observed.
    """
    cleaned = url.strip()
    if base_url:
        cleaned = urljoin(base_url, cleaned)

    parsed = urlparse(cleaned)

    # 1. Lowercase scheme and hostname
    scheme = (parsed.scheme or "http").lower()
    netloc = (parsed.netloc or "").lower()

    # Strip default ports (:80 for http, :443 for https)
    if ":" in netloc:
        host, _, port_str = netloc.partition(":")
        if (scheme == "http" and port_str == "80") or (scheme == "https" and port_str == "443"):
            netloc = host

    # 2. Normalize path
    path = parsed.path or "/"
    # Clean duplicate slashes except leading
    while "//" in path:
        path = path.replace("//", "/")

    # 3. Process query string parameters
    param_keys = []
    normalized_query = ""
    if parsed.query:
        # Extract query parameters cleanly
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        seen_keys = set()
        for k, _ in pairs:
            if k and k not in seen_keys:
                seen_keys.add(k)
                param_keys.append(k)

        param_keys.sort()

        # Re-encode query string with sorted key-value pairs
        sorted_pairs = sorted(pairs, key=lambda x: (x[0], x[1]))
        normalized_query = urlencode(sorted_pairs)

    # Reconstruct normalized URL (fragment stripped)
    normalized_url = urlunparse((scheme, netloc, path, parsed.params, normalized_query, ""))

    return normalized_url, path, param_keys
