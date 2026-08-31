"""
tests/test_target_normalizer.py

Tests for target normalizer.
"""

from app.core.constants import (
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
)
from app.services.target.normalizer import extract_target_components, normalize_target


def test_normalizer_fqdn() -> None:
    """Normalizer should lowercase domains/hostnames and strip trailing dots."""
    assert normalize_target("Example.COM", TARGET_TYPE_DOMAIN) == "example.com"
    assert normalize_target("example.com.", TARGET_TYPE_DOMAIN) == "example.com"
    assert normalize_target("API.Example.com.", TARGET_TYPE_HOSTNAME) == "api.example.com"
    assert normalize_target("sub-domain.NET", TARGET_TYPE_DOMAIN) == "sub-domain.net"


def test_normalizer_ipv4() -> None:
    """Normalizer should format IPv4 addresses canonically (e.g. resolving leading zeros)."""
    assert normalize_target("192.0.2.1", TARGET_TYPE_IPV4) == "192.0.2.1"
    # Dotted decimal octets with leading zeros are normalized
    assert normalize_target("192.168.001.005", TARGET_TYPE_IPV4) == "192.168.1.5"


def test_normalizer_ipv6() -> None:
    """Normalizer should format IPv6 addresses in compressed lowercase form and strip brackets."""
    assert normalize_target("2001:DB8:0::1", TARGET_TYPE_IPV6) == "2001:db8::1"
    assert normalize_target("[2001:db8::1]", TARGET_TYPE_IPV6) == "2001:db8::1"
    assert normalize_target("::0001", TARGET_TYPE_IPV6) == "::1"
    assert normalize_target("[::0001]", TARGET_TYPE_IPV6) == "::1"


def test_extract_target_components() -> None:
    """Test component extraction from URLs, host:port, and bare targets."""
    # Full URL
    host, scheme, port, path = extract_target_components("https://example.com:443/path")
    assert host == "example.com"
    assert scheme == "https"
    assert port == 443
    assert path == "/path"

    # Host and port
    host, scheme, port, path = extract_target_components("192.0.2.10:8080")
    assert host == "192.0.2.10"
    assert scheme is None
    assert port == 8080
    assert path is None

    # IPv6 URL
    host, scheme, port, path = extract_target_components("http://[2001:db8::1]:80/api")
    assert host == "2001:db8::1"
    assert scheme == "http"
    assert port == 80
    assert path == "/api"

