"""
tests/test_target_classifier.py

Tests for target classifier.
"""

import pytest

from app.core.constants import (
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
)
from app.core.exceptions import InvalidTargetError
from app.services.target.classifier import classify_target


def test_classifier_detects_ipv4() -> None:
    """Classifier should detect valid IPv4 addresses."""
    assert classify_target("192.0.2.1") == TARGET_TYPE_IPV4
    assert classify_target("127.0.0.1") == TARGET_TYPE_IPV4
    assert classify_target("0.0.0.0") == TARGET_TYPE_IPV4
    assert classify_target("255.255.255.255") == TARGET_TYPE_IPV4


def test_classifier_detects_ipv6() -> None:
    """Classifier should detect valid IPv6 addresses (bare or bracketed)."""
    assert classify_target("2001:db8::1") == TARGET_TYPE_IPV6
    assert classify_target("::1") == TARGET_TYPE_IPV6
    assert classify_target("[2001:db8::1]") == TARGET_TYPE_IPV6
    assert classify_target("[::1]") == TARGET_TYPE_IPV6


def test_classifier_detects_domain() -> None:
    """Classifier should detect valid domain names (exactly 2 labels)."""
    assert classify_target("example.com") == TARGET_TYPE_DOMAIN
    assert classify_target("domain.org") == TARGET_TYPE_DOMAIN
    assert classify_target("sub-domain.net") == TARGET_TYPE_DOMAIN
    # trailing dots are allowed
    assert classify_target("example.com.") == TARGET_TYPE_DOMAIN


def test_classifier_detects_hostname() -> None:
    """Classifier should detect valid hostnames (3+ labels)."""
    assert classify_target("api.example.com") == TARGET_TYPE_HOSTNAME
    assert classify_target("dev.api.example.org") == TARGET_TYPE_HOSTNAME
    assert classify_target("a.b.c.d.net") == TARGET_TYPE_HOSTNAME


def test_classifier_rejects_invalid_targets() -> None:
    """Classifier should reject malformed inputs with InvalidTargetError."""
    invalid_targets = [
        "example",          # Only 1 label
        "example.",         # Only 1 label with trailing dot
        ".example.com",     # Starts with dot
        "example..com",     # Double dot
        "example.com-",     # Label ends with hyphen
        "-example.com",     # Label starts with hyphen
        "exam_ple.com",     # Underscore in label
        "192.0.2.300",       # Invalid IPv4 octet
        "2001:db8:::1",     # Invalid IPv6 syntax
        "example.123",      # TLD must be alphabetic
        "a" * 64 + ".com",  # Label exceeds 63 characters
    ]
    for target in invalid_targets:
        with pytest.raises(InvalidTargetError):
            classify_target(target)
            
            
def test_classifier_rejects_empty_labels() -> None:
    """Classifier should reject targets containing empty DNS labels."""
    with pytest.raises(InvalidTargetError):
        classify_target("domain..com")
