"""
tests/test_target_scope_checker.py

Tests for target scope checker.
"""

import pytest

from app.core.constants import (
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
)
from app.core.exceptions import ScopeRejectedError
from app.services.target.scope_checker import ScopeChecker


def test_scope_checker_allows_public_ips_by_default() -> None:
    """Scope checker should allow public IP addresses by default."""
    checker = ScopeChecker()
    # 8.8.8.8 and 2001:4860:4860::8888 are public
    assert checker.check_scope("8.8.8.8", TARGET_TYPE_IPV4) is True
    assert checker.check_scope("2001:4860:4860::8888", TARGET_TYPE_IPV6) is True


def test_scope_checker_blocks_private_ips_when_configured() -> None:
    """Scope checker should block private IPs when allow_private_ips is False."""
    checker = ScopeChecker(allow_private_ips=False)

    # 127.0.0.1 (loopback)
    with pytest.raises(ScopeRejectedError) as exc_info:
        checker.check_scope("127.0.0.1", TARGET_TYPE_IPV4)
    assert "private or loopback IP address" in str(exc_info.value)

    # 10.0.0.1 (private RFC1918)
    with pytest.raises(ScopeRejectedError):
        checker.check_scope("10.0.0.1", TARGET_TYPE_IPV4)

    # ::1 (loopback IPv6)
    with pytest.raises(ScopeRejectedError):
        checker.check_scope("::1", TARGET_TYPE_IPV6)

    # fe80::1 (link-local IPv6)
    with pytest.raises(ScopeRejectedError):
        checker.check_scope("fe80::1", TARGET_TYPE_IPV6)


def test_scope_checker_allows_private_ips_when_configured() -> None:
    """Scope checker should allow private IPs when allow_private_ips is True."""
    checker = ScopeChecker(allow_private_ips=True)
    assert checker.check_scope("127.0.0.1", TARGET_TYPE_IPV4) is True
    assert checker.check_scope("::1", TARGET_TYPE_IPV6) is True


def test_scope_checker_enforces_exclusions() -> None:
    """Scope checker should reject targets in excluded list (exact or wildcard)."""
    checker = ScopeChecker(
        excluded_targets=["bad.com", "*.excluded.com", "192.0.2.1", "192.168.0.0/16"]
    )

    # Exact hostname exclusion
    with pytest.raises(ScopeRejectedError) as exc_info:
        checker.check_scope("bad.com", TARGET_TYPE_DOMAIN)
    assert "explicitly excluded" in str(exc_info.value)

    # Wildcard suffix exclusion
    with pytest.raises(ScopeRejectedError):
        checker.check_scope("api.excluded.com", TARGET_TYPE_HOSTNAME)
    with pytest.raises(ScopeRejectedError):
        checker.check_scope("excluded.com", TARGET_TYPE_DOMAIN)

    # Allowed domains should still pass
    assert checker.check_scope("good.com", TARGET_TYPE_DOMAIN) is True
    assert checker.check_scope("api.good.com", TARGET_TYPE_HOSTNAME) is True

    # IP exclusions
    with pytest.raises(ScopeRejectedError):
        checker.check_scope("192.0.2.1", TARGET_TYPE_IPV4)

    # Subnet exclusions
    with pytest.raises(ScopeRejectedError):
        checker.check_scope("192.168.1.100", TARGET_TYPE_IPV4)


def test_scope_checker_enforces_inclusions() -> None:
    """If allowed_targets is non-empty, only matching targets should pass."""
    checker = ScopeChecker(
        allowed_targets=["allowed.com", "*.allowed.net", "192.0.2.0/24"]
    )

    # Exact allowed domain
    assert checker.check_scope("allowed.com", TARGET_TYPE_DOMAIN) is True

    # Wildcard allowed domain
    assert checker.check_scope("api.allowed.net", TARGET_TYPE_HOSTNAME) is True

    # Allowed subnet
    assert checker.check_scope("192.0.2.55", TARGET_TYPE_IPV4) is True

    # Disallowed domains/IPs should fail
    with pytest.raises(ScopeRejectedError) as exc_info:
        checker.check_scope("forbidden.com", TARGET_TYPE_DOMAIN)
    assert "not in the allowed targets list" in str(exc_info.value)

    with pytest.raises(ScopeRejectedError):
        checker.check_scope("192.0.3.1", TARGET_TYPE_IPV4)
