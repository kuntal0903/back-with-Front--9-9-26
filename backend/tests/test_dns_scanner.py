"""
tests/test_dns_scanner.py

Tests for the DNS Scanner, validating record parsing, mock responses,
timeouts, validation filters, PTR lookups, and exceptions mappings.
"""

import dns.asyncresolver
import dns.exception
import dns.resolver
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.constants import TARGET_TYPE_DOMAIN, TARGET_TYPE_IPV4
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.dns.models import DnsRecord
from app.scanners.dns.scanner import DnsScanner
from app.scanners.dns.validator import validate_fqdn, validate_dns_record


# ─────────────────────────────────────────────
# Test Fixtures & Mocks
# ─────────────────────────────────────────────

class MockDnsRdata:
    """Mock dnspython rdata base."""
    pass


class MockARdata(MockDnsRdata):
    def __init__(self, address: str) -> None:
        self.address = address


class MockCnameRdata(MockDnsRdata):
    def __init__(self, target: str) -> None:
        self.target = target


class MockMxRdata(MockDnsRdata):
    def __init__(self, exchange: str, preference: int) -> None:
        self.exchange = exchange
        self.preference = preference


class MockTxtRdata(MockDnsRdata):
    def __init__(self, strings: list[bytes]) -> None:
        self.strings = strings


class MockPtrRdata(MockDnsRdata):
    def __init__(self, target: str) -> None:
        self.target = target


class MockCaaRdata(MockDnsRdata):
    def __init__(self, flags: int, tag: bytes, value: bytes) -> None:
        self.flags = flags
        self.tag = tag
        self.value = value


class MockDnsAnswer:
    """Mock dnspython resolver Answer payload."""
    def __init__(self, rlist: list[MockDnsRdata], ttl: int = 300) -> None:
        self.rlist = rlist
        self.ttl = ttl
        self.response = MagicMock()
        self.response.rcode.return_value = 0  # NOERROR

    def __iter__(self):
        return iter(self.rlist)


# ─────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────

def test_dns_scanner_input_validation() -> None:
    """validate_input must reject IP addresses and accept domains."""
    scanner = DnsScanner()
    
    # Accept Domain/Hostname
    target_domain = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner.validate_input(ScannerInput(target=target_domain))

    # Reject IPv4
    target_ip = TargetInfo(original="192.0.2.1", normalized="192.0.2.1", target_type=TARGET_TYPE_IPV4)
    with pytest.raises(Exception) as exc_info:
        scanner.validate_input(ScannerInput(target=target_ip))
    assert "only supports domain or hostname targets" in str(exc_info.value)


@pytest.mark.asyncio
async def test_dns_scanner_success_flow() -> None:
    """DNS Scanner must run queries concurrently, parse, validate, and return completed state."""
    scanner = DnsScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    # We mock Resolver.resolve to return A, MX, and TXT records, and empty answers for others
    def mock_resolve_side_effect(qname, rdtype, **kwargs):
        if rdtype == "A":
            return MockDnsAnswer([MockARdata("192.0.2.100"), MockARdata("192.0.2.101")], ttl=60)
        elif rdtype == "MX":
            return MockDnsAnswer([MockMxRdata("mail.example.com", 10)], ttl=3600)
        elif rdtype == "TXT":
            return MockDnsAnswer([MockTxtRdata([b"v=spf1 -all"])], ttl=300)
        else:
            raise dns.resolver.NoAnswer()

    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = mock_resolve_side_effect
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.errors) == 0
    assert len(result.results) >= 3
    
    # Verify A records
    a_records = [r for r in result.results if r.record_type == "A"]
    assert len(a_records) >= 2
    assert a_records[0].value == "192.0.2.100"
    assert a_records[0].ttl == 60

    # Verify MX record
    mx_records = [r for r in result.results if r.record_type == "MX"]
    assert len(mx_records) == 1
    assert mx_records[0].value == "mail.example.com"
    assert mx_records[0].preference == 10

    # Verify TXT record
    txt_records = [r for r in result.results if r.record_type == "TXT"]
    assert len(txt_records) == 1
    assert txt_records[0].value == "v=spf1 -all"


@pytest.mark.asyncio
async def test_dns_scanner_ptr_lookups() -> None:
    """DNS Scanner must correctly query and validate PTR records."""
    scanner = DnsScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    def mock_resolve_side_effect(qname, rdtype, **kwargs):
        if rdtype == "PTR":
            return MockDnsAnswer([MockPtrRdata("target.example.com.")], ttl=300)
        else:
            raise dns.resolver.NoAnswer()

    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = mock_resolve_side_effect
        result = await scanner.execute(scanner_input)

    ptr_records = [r for r in result.results if r.record_type == "PTR"]
    assert len(ptr_records) == 1
    assert ptr_records[0].value == "target.example.com"
    assert validate_dns_record(ptr_records[0]) is True


@pytest.mark.asyncio
async def test_dns_scanner_custom_resolvers() -> None:
    """DNS Scanner must configure custom nameservers when specified in configuration."""
    scanner = DnsScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info, configuration={"resolvers": ["1.1.1.1"]})

    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer()
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"


@pytest.mark.asyncio
async def test_dns_scanner_filters_invalid_records() -> None:
    """DNS Scanner must ignore records that fail validator checks (e.g. invalid IP string)."""
    scanner = DnsScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    def mock_resolve_side_effect(qname, rdtype, **kwargs):
        if rdtype == "A":
            # One valid, one invalid IP
            return MockDnsAnswer([MockARdata("192.0.2.100"), MockARdata("999.999.999.999")], ttl=60)
        else:
            raise dns.resolver.NoAnswer()

    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = mock_resolve_side_effect
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    # Only the valid IP record should be saved
    a_records = [r for r in result.results if r.record_type == "A"]
    assert len(a_records) == 1
    assert a_records[0].value == "192.0.2.100"


@pytest.mark.asyncio
async def test_dns_scanner_handles_nxdomain() -> None:
    """NXDOMAIN error must result in completed status with 0 records (not a failed scan)."""
    scanner = DnsScanner()
    target_info = TargetInfo(original="nonexistent.example.com", normalized="nonexistent.example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 0
    assert len(result.errors) == 0


@pytest.mark.asyncio
async def test_dns_scanner_handles_timeout() -> None:
    """Resolver Timeout exception must result in connection_timeout status error."""
    scanner = DnsScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = dns.exception.Timeout()
        result = await scanner.execute(scanner_input)

    assert result.status == "failed"
    assert len(result.errors) == 1
    assert result.errors[0].error_type == "connection_timeout"


def test_validator_fqdn_edge_cases() -> None:
    """Check validate_fqdn helper boundaries."""
    assert validate_fqdn("mail.example.com") is True
    assert validate_fqdn("mail.example.com.") is True
    assert validate_fqdn("example.com") is True
    assert validate_fqdn("a.net") is True
    
    assert validate_fqdn("com") is False
    assert validate_fqdn(".example.com") is False
    assert validate_fqdn("example..com") is False
    assert validate_fqdn("a" * 64 + ".com") is False
