"""
tests/test_tls_scanner.py

Tests for the TLS/Certificate Scanner, validating certificate expiration dates parsing,
hostname wildcard matching, self-signed validation, and mock handshakes.
"""

import ssl
import pytest
from unittest.mock import MagicMock, patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.tls.models import CertDetails
from app.scanners.tls.scanner import TlsScanner
from app.scanners.tls.validator import (
    evaluate_trust_status,
    parse_ssl_date,
)


# ─────────────────────────────────────────────
# Unit Tests for Cert Validator
# ─────────────────────────────────────────────

def test_parse_ssl_date() -> None:
    """Validator must parse standard SSL GMT date formats correctly."""
    dt = parse_ssl_date("Apr 12 23:59:59 2015 GMT")
    assert dt.year == 2015
    assert dt.month == 4
    assert dt.day == 12
    assert dt.hour == 23

    dt_utc = parse_ssl_date("Dec 31 10:00:00 2026 UTC")
    assert dt_utc.year == 2026
    assert dt_utc.month == 12
    assert dt_utc.day == 31


def test_evaluate_trust_expired() -> None:
    """Validator must flag certificates that have expired validity dates."""
    cert = CertDetails(
        subject={"commonName": "expired.com"},
        issuer={"commonName": "Authority CA"},
        validity_end="Jan 01 00:00:00 2020 GMT",
    )
    status = evaluate_trust_status("expired.com", cert)
    assert status == "expired"


def test_evaluate_trust_self_signed() -> None:
    """Validator must flag certificates where Issuer CN equals Subject CN."""
    cert = CertDetails(
        subject={"commonName": "myhost.local", "organizationName": "Self"},
        issuer={"commonName": "myhost.local", "organizationName": "Self"},
        validity_end="Dec 31 23:59:59 2035 GMT",
    )
    status = evaluate_trust_status("myhost.local", cert)
    assert status == "self_signed"


def test_evaluate_trust_hostname_mismatch() -> None:
    """Validator must flag hostname mismatches using wildcard domain mapping rules."""
    cert = CertDetails(
        subject={"commonName": "*.mismatch.com"},
        issuer={"commonName": "Authority CA"},
        validity_end="Dec 31 23:59:59 2035 GMT",
        subject_alt_names=["*.mismatch.com"],
    )

    # Match wildcard
    assert evaluate_trust_status("sub.mismatch.com", cert) == "valid"

    # Mismatch nested sub
    assert evaluate_trust_status("nested.sub.mismatch.com", cert) == "hostname_mismatch"

    # Mismatch unrelated domain
    assert evaluate_trust_status("other.com", cert) == "hostname_mismatch"


# ─────────────────────────────────────────────
# Integration Scanner Mock Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tls_scanner_success_flow() -> None:
    """TLS Scanner must run handshakes, call decoders, validate ciphers, and format evidence."""
    scanner = TlsScanner()
    target_info = TargetInfo(original="google.com", normalized="google.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    # Mock cert details return
    mock_cert = CertDetails(
        subject={"commonName": "google.com"},
        issuer={"commonName": "GTS CA"},
        serial_number="12345",
        validity_start="Jan 01 00:00:00 2026 GMT",
        validity_end="Dec 31 23:59:59 2026 GMT",
        subject_alt_names=["google.com", "www.google.com"],
    )

    # Patch handshake execution
    with patch(
        "app.scanners.tls.scanner.execute_tls_handshake",
        return_value=(b"dercertbytes", "TLSv1.3", "ECDHE-RSA-AES128-GCM-SHA256"),
    ):
        # Patch certificate binary decoder
        with patch("app.scanners.tls.scanner.parse_der_certificate", return_value=mock_cert):
            # Patch validator protocols/ciphers probes to keep tests local and fast
            with patch("app.scanners.tls.scanner.probe_supported_protocols", return_value=["TLSv1.2", "TLSv1.3"]):
                with patch("app.scanners.tls.scanner.probe_weak_ciphers", return_value=(False, [])):
                    result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.errors) == 0
    assert len(result.results) == 1

    rec = result.results[0]
    assert rec.port == 443
    assert rec.host == "google.com"
    assert rec.negotiated_tls_version == "TLSv1.3"
    assert rec.certificate.subject["commonName"] == "google.com"
    assert rec.supported_protocols == ["TLSv1.2", "TLSv1.3"]
    assert rec.weak_ciphers_accepted is False
    assert rec.trust_status == "valid"

    # Evidence checks
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.raw_evidence["host"] == "google.com"
    assert evidence.raw_evidence["negotiated_version"] == "TLSv1.3"
    assert evidence.raw_evidence["weak_ciphers_accepted"] is False
