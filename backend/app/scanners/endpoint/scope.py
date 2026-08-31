"""
app/scanners/endpoint/scope.py

Enforces crawling boundaries (same-origin hostname and path filtering).
"""

from urllib.parse import urlparse

# Extensions pointing to non-text media or executable binary assets
BINARY_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".bin", ".dmg", ".iso",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm",
)


def is_url_in_scope(candidate_url: str, seed_url: str, allow_subdomains: bool = False) -> bool:
    """
    Check if a candidate URL belongs to the same target domain/netloc as the seed URL
    and is not a binary static file asset.
    
    Args:
        candidate_url: The URL to evaluate.
        seed_url: The crawl starting/originating seed URL.
        allow_subdomains: If True, allows subdomains of seed_url. Default False.
        
    Returns:
        bool: True if in scope. False if external domain or binary asset.
    """
    try:
        parsed_cand = urlparse(candidate_url)
        parsed_seed = urlparse(seed_url)

        # 1. Compare hosts (netlocs)
        cand_host = (parsed_cand.hostname or "").lower()
        seed_host = (parsed_seed.hostname or "").lower()

        if not cand_host or not seed_host:
            return False

        if cand_host != seed_host:
            if allow_subdomains and cand_host.endswith("." + seed_host):
                pass
            else:
                return False

        # 2. Filter out binary static assets by path suffix
        path_lower = parsed_cand.path.lower()
        if path_lower.endswith(BINARY_EXTENSIONS):
            return False

        # 3. Only crawl standard web schemes
        if parsed_cand.scheme not in ("http", "https"):
            return False

        return True
    except Exception:
        return False
