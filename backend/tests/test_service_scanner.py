"""
tests/test_service_scanner.py

Tests for the Service Identification Scanner, validating regex signatures,
banner grabs, mock socket interactions, TLS support, and negative tests.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.constants import TARGET_TYPE_IPV4
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.service.scanner import ServiceScanner
from app.scanners.service.validator import match_service_signature


# ─────────────────────────────────────────────
# Unit Tests for Signature Matching
# ─────────────────────────────────────────────

def test_signature_matcher_ssh() -> None:
    """Matcher should extract SSH protocol and OpenSSH version correctly."""
    banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    res = match_service_signature(22, banner)
    assert res["protocol"] == "ssh"
    assert res["software_name"] == "OpenSSH"
    assert res["software_version"] == "8.2p1"
    assert res["extra"]["ssh_protocol"] == "2.0"

    banner_other = "SSH-2.0-Dropbear_2020.81"
    res_other = match_service_signature(22, banner_other)
    assert res_other["protocol"] == "ssh"
    assert res_other["software_name"] == "Dropbear"
    assert res_other["software_version"] == "2020.81"


def test_signature_matcher_http() -> None:
    """Matcher should parse HTTP Server headers (nginx, apache, iis)."""
    banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n"
    res = match_service_signature(80, banner)
    assert res["protocol"] == "http"
    assert res["software_name"] == "nginx"
    assert res["software_version"] == "1.18.0"

    banner_apache = "HTTP/1.1 301 Moved Permanently\r\nServer: Apache/2.4.41 (Ubuntu)\r\nLocation: https://example.com\r\n\r\n"
    res_apache = match_service_signature(80, banner_apache)
    assert res_apache["protocol"] == "http"
    assert res_apache["software_name"] == "Apache"
    assert res_apache["software_version"] == "2.4.41"


def test_signature_matcher_smtp() -> None:
    """Matcher should parse SMTP 220 greeting headers."""
    banner = "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
    res = match_service_signature(25, banner)
    assert res["protocol"] == "smtp"
    assert res["software_name"] == "Postfix"
    assert res["extra"]["hostname"] == "mail.example.com"


def test_signature_matcher_ftp() -> None:
    """Matcher should parse FTP 220 greeting headers."""
    banner = "220 (vsFTPd 3.0.3)\r\n"
    res = match_service_signature(21, banner)
    assert res["protocol"] == "ftp"
    assert res["software_name"] == "vsFTPd"
    assert res["software_version"] == "3.0.3"


def test_signature_matcher_fallback() -> None:
    """Matcher should fallback to unknown when banner is unrecognized."""
    banner = "unrecognized junk data payload\n"
    res = match_service_signature(9999, banner)
    assert res["protocol"] == "unknown"
    assert res["software_name"] is None
    assert res["software_version"] is None


# ─────────────────────────────────────────────
# Negative Tests (Section 43)
# ─────────────────────────────────────────────

def test_negative_no_version_when_absent() -> None:
    """Matcher MUST NOT report a version string if the server header only states 'Server: nginx'."""
    banner = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
    res = match_service_signature(80, banner)
    assert res["protocol"] == "http"
    assert res["software_name"] == "nginx"
    assert res["software_version"] is None  # MUST NOT guess version!


def test_negative_no_ssh_without_banner() -> None:
    """Matcher MUST NOT claim SSH protocol for port 22 if the banner is unrecognized junk."""
    banner = "Welcome to arbitrary TCP server\r\n"
    res = match_service_signature(22, banner)
    assert res["protocol"] != "ssh"
    assert res["protocol"] == "unknown"


# ─────────────────────────────────────────────
# Integration / Mock Server Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_service_scanner_success_flow() -> None:
    """Service Scanner must grab SSH and HTTP banners and parse them successfully."""
    scanner = ServiceScanner()
    target_info = TargetInfo(original="192.0.2.1", normalized="192.0.2.1", target_type=TARGET_TYPE_IPV4)
    
    scanner_input = ScannerInput(
        target=target_info,
        configuration={
            "ports": [22, 80],
            "timeout": 0.5,
        }
    )

    async def mock_open_connection(host, port, **kwargs):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.drain = AsyncMock()

        if port == 22:
            mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.2p1\n")
        elif port == 80:
            mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n")
            
        return mock_reader, mock_writer

    with patch("asyncio.open_connection", side_effect=mock_open_connection):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.errors) == 0
    assert len(result.results) == 2

    # Verify SSH
    ssh_rec = result.results[0]
    assert ssh_rec.port == 22
    assert ssh_rec.protocol == "ssh"
    assert ssh_rec.software_name == "OpenSSH"
    assert ssh_rec.software_version == "8.2p1"

    # Verify HTTP
    http_rec = result.results[1]
    assert http_rec.port == 80
    assert http_rec.protocol == "http"
    assert http_rec.software_name == "nginx"
    assert http_rec.software_version == "1.18.0"

    # Verify evidence
    assert len(result.evidence) == 2
    assert result.evidence[0].raw_evidence["port"] == 22
    assert result.evidence[1].raw_evidence["port"] == 80


@pytest.mark.asyncio
async def test_service_scanner_handles_empty_banner() -> None:
    """Service Scanner must ignore ports that return empty banners (no service reported)."""
    scanner = ServiceScanner()
    target_info = TargetInfo(original="192.0.2.1", normalized="192.0.2.1", target_type=TARGET_TYPE_IPV4)
    scanner_input = ScannerInput(target=target_info)

    async def mock_open_connection(host, port, **kwargs):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")  # EOF immediately
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        return mock_reader, mock_writer

    with patch("asyncio.open_connection", side_effect=mock_open_connection), \
         patch("app.scanners.service.client.check_tls_wrapper", return_value=(False, None, None)):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 0
    assert len(result.evidence) == 0
