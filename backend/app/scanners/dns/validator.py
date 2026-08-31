"""
app/scanners/dns/validator.py

Validates individual DNS records parsed from query responses.
Ensures we don't return malformed values or trust bad resolver answers.
"""

import ipaddress
import re

from app.scanners.dns.models import DnsRecord

# Basic label validation for hostname values
_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def validate_fqdn(hostname: str) -> bool:
    """
    Validate if a target hostname returned from DNS is syntactically a valid FQDN.
    """
    name = hostname.rstrip(".")
    if not name:
        return False
    
    labels = name.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if not _LABEL_PATTERN.match(label):
            return False

    # TLD must be alphabetic/alphanumeric and at least 2 characters
    tld = labels[-1]
    return tld.isalnum() and not tld.isdigit() and len(tld) >= 2


def validate_dns_record(record: DnsRecord) -> bool:
    """
    Validate a resolved record value against its type constraint.
    
    Args:
        record: Parsed DnsRecord instance.
        
    Returns:
        True if record content passes validity checks.
    """
    val = record.value.strip()
    rtype = record.record_type.upper()

    if rtype == "A":
        try:
            ipaddress.IPv4Address(val)
            return True
        except ValueError:
            return False

    elif rtype == "AAAA":
        try:
            ipaddress.IPv6Address(val)
            return True
        except ValueError:
            return False

    elif rtype in ("CNAME", "MX", "NS", "PTR"):
        # Strip trailing dot if present for standard FQDN validation
        return validate_fqdn(val)

    # For TXT, SOA, CAA: we accept any structurally successfully parsed value.
    return True
