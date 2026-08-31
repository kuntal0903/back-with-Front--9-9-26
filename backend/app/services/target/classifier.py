"""
app/services/target/classifier.py

Target type classifier.

Responsibility: determine what kind of target a validated string represents.

Possible target types (from constants.py):
  - TARGET_TYPE_IPV4    — e.g., 192.0.2.10
  - TARGET_TYPE_IPV6    — e.g., 2001:db8::1
  - TARGET_TYPE_DOMAIN  — e.g., example.com  (exactly 2 DNS labels)
  - TARGET_TYPE_HOSTNAME — e.g., api.example.com  (3+ DNS labels)

Classification rules:
  1. Try IPv4 first (using ipaddress module — authoritative, no guessing)
  2. Try IPv6 second (brackets are stripped for IPv6 like [::1])
  3. Try FQDN (domain/hostname) using RFC-compliant label validation
  4. If none match → raise InvalidTargetError

This module does NOT normalize — only classify.

Flow:
    STRIPPED INPUT
        ↓
    CLASSIFY (this module)
        ↓
    TARGET_TYPE constant
        or
    InvalidTargetError
"""

import ipaddress
import re

from app.core.constants import (
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
)
from app.core.exceptions import InvalidTargetError

# RFC 1035 label rules:
#   - 1 to 63 characters
#   - Alphanumeric or hyphen
#   - Must not start or end with a hyphen
# Handles single-char labels (just [a-zA-Z0-9]) and multi-char labels.
_LABEL_RE: re.Pattern[str] = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# TLD must be all-alphabetic, 2+ characters.
# (Numeric TLDs are not valid in standard DNS.)
_TLD_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z]{2,}$")


# Dotted-decimal pattern with 1-3 digits per octet, allowing leading zeros.
_IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _try_ipv4(value: str) -> bool:
    """Return True if value is a valid IPv4 address (handles leading zeros)."""
    if not _IPV4_PATTERN.match(value):
        return False
    try:
        # Pre-strip leading zeros to avoid AddressValueError in ipaddress module
        sanitized = ".".join(str(int(part)) for part in value.split("."))
        ipaddress.IPv4Address(sanitized)
        return True
    except ValueError:
        return False


def _try_ipv6(value: str) -> bool:
    """
    Return True if value is a valid IPv6 address.

    Accepts both bare form (::1) and bracket form ([::1]).
    """
    candidate = value.strip("[]")
    try:
        ipaddress.IPv6Address(candidate)
        return True
    except ValueError:
        return False


def _classify_fqdn(value: str) -> str | None:
    """
    Attempt to classify value as a domain or hostname.

    Args:
        value: A stripped target string that is not an IP address.

    Returns:
        TARGET_TYPE_DOMAIN if exactly 2 labels.
        TARGET_TYPE_HOSTNAME if 3 or more labels.
        None if the value does not match a valid FQDN structure.
    """
    # Strip optional trailing dot (FQDN notation, e.g. "example.com.")
    name = value.rstrip(".")

    if not name:
        return None

    labels = name.split(".")

    # Must have at least 2 labels (label + TLD).
    if len(labels) < 2:
        return None

    # Validate each label.
    for label in labels:
        if not label:
            # Empty label means a double dot (e.g. "example..com")
            return None
        if len(label) > 63:
            return None
        if not _LABEL_RE.match(label):
            return None

    # TLD must be alphabetic.
    tld = labels[-1]
    if not _TLD_RE.match(tld):
        return None

    # Exactly 2 labels → apex domain (e.g. example.com)
    # 3+ labels → hostname with subdomain (e.g. api.example.com)
    return TARGET_TYPE_DOMAIN if len(labels) == 2 else TARGET_TYPE_HOSTNAME


from app.services.target.normalizer import extract_target_components


def classify_target(value: str) -> str:
    """
    Classify a validated target string into a specific target type.

    Classification order:
      1. IPv4
      2. IPv6 (bare or bracket form)
      3. FQDN (domain or hostname)

    Args:
        value: A stripped, non-empty target string (from validator.py or URL/host:port).

    Returns:
        One of: TARGET_TYPE_IPV4, TARGET_TYPE_IPV6,
                TARGET_TYPE_DOMAIN, TARGET_TYPE_HOSTNAME

    Raises:
        InvalidTargetError: If the value does not match any known target type.
    """
    host_str, _, _, _ = extract_target_components(value)

    if _try_ipv4(host_str):
        return TARGET_TYPE_IPV4

    if _try_ipv6(host_str):
        return TARGET_TYPE_IPV6

    fqdn_type = _classify_fqdn(host_str)
    if fqdn_type is not None:
        return fqdn_type

    raise InvalidTargetError(
        f"'{value}' is not a recognized target. "
        "Expected a domain (example.com), hostname (api.example.com), "
        "IPv4 address (192.0.2.1), or IPv6 address (2001:db8::1)."
    )
