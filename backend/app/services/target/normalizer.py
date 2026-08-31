"""
app/services/target/normalizer.py

Target normalizer.

Responsibility: produce a canonical, consistent representation of a target
so that "Example.COM", "example.com.", and "example.com" are treated as
the same target throughout the system.

Normalization rules by type:
  - IPv4:     Canonical decimal notation (strips leading zeros if any)
              e.g.  "192.168.001.001" → "192.168.1.1"
  - IPv6:     Compressed lowercase form
              e.g.  "2001:0DB8:0000::0001" → "2001:db8::1"
              Brackets are stripped: "[::1]" → "::1"
  - DOMAIN:   Lowercase, trailing dot removed
              e.g.  "Example.COM." → "example.com"
  - HOSTNAME: Lowercase, trailing dot removed
              e.g.  "API.Example.COM" → "api.example.com"

The original input is always preserved separately so nothing is lost.

Flow:
    STRIPPED INPUT + TARGET_TYPE
        ↓
    NORMALIZE (this module)
        ↓
    NORMALIZED STRING
"""

import ipaddress
from urllib.parse import urlparse

from app.core.constants import TARGET_TYPE_IPV4, TARGET_TYPE_IPV6


def extract_target_components(value: str) -> tuple[str, str | None, int | None, str | None]:
    """
    Extract target components (host_str, scheme, port, path) from raw or cleaned input.

    Supports bare targets ("example.com", "192.0.2.10", "[2001:db8::1]"),
    host:port targets ("example.com:443", "192.0.2.10:8080"),
    and full URLs ("https://example.com:443/path", "http://192.0.2.10:8080/api").
    """
    cleaned = value.strip()
    scheme = None
    port = None
    path = None

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        scheme = parsed.scheme.lower() if parsed.scheme else None
        host_str = parsed.hostname or ""
        port = parsed.port
        path = parsed.path if parsed.path else None
    elif ":" in cleaned and not cleaned.startswith("[") and not (cleaned.startswith("::") or "::" in cleaned):
        # host:port check (e.g. "example.com:443" or "192.0.2.10:8080")
        parts = cleaned.rsplit(":", 1)
        if parts[1].isdigit():
            host_str = parts[0].strip("[]")
            port = int(parts[1])
        else:
            host_str = cleaned.strip("[]")
    else:
        host_str = cleaned.strip("[]")

    return host_str, scheme, port, path


def normalize_target(value: str, target_type: str) -> str:
    """
    Normalize a target to its canonical form.

    Args:
        value:       Stripped input string (from validator.py).
        target_type: One of the TARGET_TYPE_* constants (from classifier.py).

    Returns:
        The normalized string representation of the target.
    """
    if target_type == TARGET_TYPE_IPV4:
        return _normalize_ipv4(value)

    if target_type == TARGET_TYPE_IPV6:
        return _normalize_ipv6(value)

    # Domain or hostname: lowercase + strip trailing dot
    return _normalize_fqdn(value)


def _normalize_ipv4(value: str) -> str:
    """
    Normalize an IPv4 address to canonical dotted-decimal form.

    Strips any leading zeros from octets.
    """
    sanitized = ".".join(str(int(part)) for part in value.split("."))
    return str(ipaddress.IPv4Address(sanitized))


def _normalize_ipv6(value: str) -> str:
    """
    Normalize an IPv6 address to compressed lowercase form.

    Handles both bare (::1) and bracketed ([::1]) forms.
    """
    candidate = value.strip("[]")
    return str(ipaddress.IPv6Address(candidate))


def _normalize_fqdn(value: str) -> str:
    """
    Normalize a domain or hostname.

    - Lowercase all characters
    - Remove trailing dot (FQDN notation)
    """
    return value.rstrip(".").lower()
