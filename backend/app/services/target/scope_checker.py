"""
app/services/target/scope_checker.py

Scope validator.

Responsibility: Determine if a target is authorized/allowed for scanning.
It checks targets against configuration rules (allowed/excluded domains, IPs, subnets).
Also enforces safety checks: blocking loopback and private addresses by default,
especially in non-development environments.

Flow:
    NORMALIZED STRING + TARGET_TYPE
        ↓
    CHECK SCOPE (this module)
        ↓
    True (allowed) or ScopeRejectedError
"""

import ipaddress
import re
from typing import Any, Sequence

from app.core.config import settings
from app.core.constants import TARGET_TYPE_IPV4, TARGET_TYPE_IPV6
from app.core.exceptions import ScopeRejectedError


def is_private_ip(ip_str: str) -> bool:
    """
    Check if an IP string is a loopback, private, link-local, or multicast address.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def matches_domain_pattern(hostname: str, pattern: str) -> bool:
    """
    Check if a hostname matches a domain pattern.
    Supports wildcards like *.example.com or exact matches.
    """
    hostname = hostname.lower()
    pattern = pattern.lower()

    if pattern.startswith("*."):
        suffix = pattern[1:]  # e.g., ".example.com"
        return hostname.endswith(suffix) or hostname == suffix[1:]
    
    return hostname == pattern


def is_ip_in_subnet(ip_str: str, subnet_str: str) -> bool:
    """
    Check if an IP address resides within a given CIDR subnet.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        subnet = ipaddress.ip_network(subnet_str, strict=False)
        return ip in subnet
    except ValueError:
        return False


class ScopeChecker:
    """
    Enforces authorization scope rules.
    Loads configurations and evaluates whether a normalized target is allowed.
    """

    def __init__(
        self,
        allowed_targets: Sequence[str] | None = None,
        excluded_targets: Sequence[str] | None = None,
        allow_private_ips: bool | None = None,
    ) -> None:
        """
        Initialize scope checker with explicit rules.
        If parameters are None, it defaults to settings.
        """
        # In a real app, allowed/excluded targets might come from config.
        # We will initialize with empty lists if not provided.
        self.allowed_targets = allowed_targets or []
        self.excluded_targets = excluded_targets or []
        
        # Default behavior: block private/loopback IPs in production,
        # but allow in development/testing if configured.
        if allow_private_ips is not None:
            self.allow_private_ips = allow_private_ips
        else:
            self.allow_private_ips = settings.is_development or settings.is_test

    def check_scope(self, normalized_target: str, target_type: str) -> bool:
        """
        Evaluate if the normalized target is allowed.

        Args:
            normalized_target: Canonical target string.
            target_type: Classified target type (from constants.py).

        Returns:
            True if target is allowed.

        Raises:
            ScopeRejectedError: If target is not allowed or explicitly excluded.
        """
        # 1. Enforce safety checks on IP targets
        if target_type in (TARGET_TYPE_IPV4, TARGET_TYPE_IPV6):
            if not self.allow_private_ips and is_private_ip(normalized_target):
                raise ScopeRejectedError(
                    f"Target '{normalized_target}' is a private or loopback IP address, "
                    "which is not allowed in this environment."
                )

        # 2. Check explicit exclusions (Exclusions take priority)
        for exclusion in self.excluded_targets:
            if target_type in (TARGET_TYPE_IPV4, TARGET_TYPE_IPV6):
                # Try subnet match first, then exact string match
                if "/" in exclusion:
                    if is_ip_in_subnet(normalized_target, exclusion):
                        raise ScopeRejectedError(
                            f"Target '{normalized_target}' matches excluded subnet '{exclusion}'."
                        )
                elif normalized_target == exclusion:
                    raise ScopeRejectedError(
                        f"Target '{normalized_target}' matches explicitly excluded target '{exclusion}'."
                    )
            else:
                # FQDN match
                if matches_domain_pattern(normalized_target, exclusion):
                    raise ScopeRejectedError(
                        f"Target '{normalized_target}' matches explicitly excluded domain '{exclusion}'."
                    )

        # 3. Check explicit inclusions
        # If allowed_targets is empty, default is to allow all targets (except safety checks)
        if not self.allowed_targets:
            return True

        for allowed in self.allowed_targets:
            if target_type in (TARGET_TYPE_IPV4, TARGET_TYPE_IPV6):
                if "/" in allowed:
                    if is_ip_in_subnet(normalized_target, allowed):
                        return True
                elif normalized_target == allowed:
                    return True
            else:
                if matches_domain_pattern(normalized_target, allowed):
                    return True

        # If allowed_targets is specified, but target did not match any of them
        raise ScopeRejectedError(
            f"Target '{normalized_target}' is not in the allowed targets list."
        )
