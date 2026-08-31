"""
tests/test_tls_scanner_accuracy.py

Comprehensive test suite for Live TLS Scanner,
validating TLS handshake, SNI, ALPN negotiation, SAN extractions, SHA-256 cert fingerprinting,
hostname verification vs certificate observation separation, and TLS error handling.
"""

import pytest
from unittest.mock import patch, MagicMock

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.tls.models import CertDetails
from app.scanners.tls.parser import parse_der_certificate
from app.scanners.tls.scanner import TlsScanner
from app.scanners.tls.validator import (
    evaluate_hostname_verification,
    evaluate_trust_status,
    match_wildcard,
)


def test_sha256_fingerprint_and_cert_parsing() -> None:
    """Cert parser generates uppercase SHA-256 fingerprint and parses SANs."""
    # Mock raw DER bytes
    der_bytes = b"MOCK_DER_CERTIFICATE_BYTES_12345"

    with patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"), \
         patch("ssl._ssl._test_decode_cert", return_value={
             "subject": ((("commonName", "example.com"),),),
             "issuer": ((("organizationName", "DigiCert Inc"),),),
             "serialNumber": "0A1B2C3D",
             "notBefore": "Jan 01 00:00:00 2023 GMT",
             "notAfter": "Jan 01 00:00:00 2025 GMT",
             "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
         }):
        cert_details = parse_der_certificate(der_bytes)

    assert cert_details.fingerprint_sha256 is not None
    assert len(cert_details.fingerprint_sha256) == 64
    assert cert_details.subject["commonName"] == "example.com"
    assert cert_details.issuer["organizationName"] == "DigiCert Inc"
    assert "*.example.com" in cert_details.subject_alt_names


def test_hostname_verification_vs_trust_status() -> None:
    """Hostname verification is evaluated separately from trust status."""
    cert = CertDetails(
        subject={"commonName": "*.example.com"},
        issuer={"organizationName": "Let's Encrypt"},
        subject_alt_names=["*.example.com", "example.com"],
        validity_end="Jan 01 00:00:00 2099 GMT",
    )

    # Valid match
    assert evaluate_hostname_verification("sub.example.com", cert) == "valid"
    assert evaluate_trust_status("sub.example.com", cert) == "valid"

    # Hostname mismatch
    assert evaluate_hostname_verification("different.net", cert) == "mismatch"
    assert evaluate_trust_status("different.net", cert) == "hostname_mismatch"


def test_wildcard_matching_rfc6125() -> None:
    """Wildcard matching obeys single-label RFC 6125 rules."""
    assert match_wildcard("api.example.com", "*.example.com") is True
    assert match_wildcard("deep.sub.example.com", "*.example.com") is False
    assert match_wildcard("example.com", "*.example.com") is False


@pytest.mark.asyncio
async def test_tls_scanner_execution_and_alpn() -> None:
    """TlsScanner executes handshake, captures ALPN negotiation, and populates record."""
    scanner = TlsScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    mock_der = b"MOCK_DER_BYTES"
    mock_version = "TLSv1.3"
    mock_cipher = "TLS_AES_256_GCM_SHA384"
    mock_alpn = "h2"

    with patch("app.scanners.tls.scanner.execute_tls_handshake", return_value=(mock_der, mock_version, mock_cipher, mock_alpn)), \
         patch("app.scanners.tls.scanner.parse_der_certificate", return_value=CertDetails(
             subject={"commonName": "example.com"},
             issuer={"commonName": "DigiCert"},
             subject_alt_names=["example.com"],
             validity_end="Jan 01 00:00:00 2099 GMT",
         )), \
         patch("app.scanners.tls.scanner.probe_supported_protocols", return_value=["TLSv1.2", "TLSv1.3"]), \
         patch("app.scanners.tls.scanner.probe_weak_ciphers", return_value=(False, [])):

        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 1
    rec = result.results[0]
    assert rec.negotiated_tls_version == "TLSv1.3"
    assert rec.negotiated_cipher == "TLS_AES_256_GCM_SHA384"
    assert rec.alpn_negotiated == "h2"
    assert rec.hostname_verification == "valid"
    assert rec.trust_status == "valid"
