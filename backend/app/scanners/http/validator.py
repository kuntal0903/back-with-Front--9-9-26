"""
app/scanners/http/validator.py

Validates URL parameters and configurations for the HTTP/HTTPS Scanner.
"""

from urllib.parse import urlparse

from app.scanners.base.exceptions import ScannerInputValidationError


def validate_url(url: str) -> str:
    """
    Syntactically check and clean a target URL.
    
    Args:
        url: Raw URL string.
        
    Returns:
        str: Cleansed URL.
        
    Raises:
        ScannerInputValidationError: If scheme is not HTTP/HTTPS or hostname is missing.
    """
    cleaned = url.strip()
    parsed = urlparse(cleaned)

    if parsed.scheme not in ("http", "https"):
        raise ScannerInputValidationError(
            f"Invalid URL scheme '{parsed.scheme}'. Scheme must be http or https."
        )

    if not parsed.netloc:
        raise ScannerInputValidationError(
            f"Invalid URL '{cleaned}'. Missing target domain or host netloc."
        )

    return cleaned
