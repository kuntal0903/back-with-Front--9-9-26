"""
tests/test_port_scanner.py

Tests for the Port Discovery Scanner, validating port lists, ranges,
mock connection outcomes, state classifications, profiles, and retries.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.constants import TARGET_TYPE_IPV4
from app.schemas.scan_request import TargetInfo
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput
from app.scanners.port.models import PortDiscoveryRecord
from app.scanners.port.scanner import PortScanner
from app.scanners.port.validator import validate_ports


# ─────────────────────────────────────────────
# Unit Tests for Validator
# ─────────────────────────────────────────────

def test_port_validator_deduplicates_and_sorts() -> None:
    """Validator must deduplicate and sort given port lists."""
    assert validate_ports([443, 80, 443, 22]) == [22, 80, 443]


def test_port_validator_rejects_out_of_range() -> None:
    """Validator must raise ScannerInputValidationError if port is out of range."""
    with pytest.raises(ScannerInputValidationError) as exc_info:
        validate_ports([80, 70000])
    assert "out of range" in str(exc_info.value)

    with pytest.raises(ScannerInputValidationError):
        validate_ports([80, 0])


def test_port_validator_rejects_non_integers() -> None:
    """Validator must raise ScannerInputValidationError if port is not an integer."""
    with pytest.raises(ScannerInputValidationError):
        validate_ports([80, "22"])  # type: ignore

    with pytest.raises(ScannerInputValidationError):
        validate_ports([80, True])  # type: ignore (bool is subclass of int)


# ─────────────────────────────────────────────
# Integration / Mock Connection Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_port_scanner_success_flow() -> None:
    """Port Scanner must report open, closed, and filtered states correctly based on socket outcomes."""
    scanner = PortScanner()
    target_info = TargetInfo(original="192.0.2.1", normalized="192.0.2.1", target_type=TARGET_TYPE_IPV4)
    
    # Configure custom ports to scan: 80 (open), 22 (closed), 443 (timeout/filtered)
    scanner_input = ScannerInput(
        target=target_info,
        configuration={
            "ports": [80, 22, 443],
            "timeout": 0.5,
            "max_concurrency": 2,
            "max_retries": 0,
        }
    )

    async def mock_open_connection(host, port):
        if port == 80:
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            return AsyncMock(), mock_writer
        elif port == 22:
            raise ConnectionRefusedError()
        elif port == 443:
            await asyncio.sleep(1.0)
            raise asyncio.TimeoutError()

    with patch("asyncio.open_connection", side_effect=mock_open_connection):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.errors) == 0
    assert len(result.results) == 3

    # Check port 22 (closed)
    port_22 = result.results[0]
    assert port_22.port == 22
    assert port_22.state == "closed"
    assert port_22.reason == "connection_refused"
    assert port_22.service_hint == "ssh"

    # Check port 80 (open)
    port_80 = result.results[1]
    assert port_80.port == 80
    assert port_80.state == "open"
    assert port_80.reason == "connection_accepted"
    assert port_80.method == "tcp_connect"
    assert port_80.service_hint == "http"

    # Check port 443 (filtered/timeout)
    port_443 = result.results[2]
    assert port_443.port == 443
    assert port_443.state == "filtered"
    assert port_443.reason == "timeout"
    assert port_443.service_hint == "https"

    # Evidence must only be gathered for the open port (80)
    assert len(result.evidence) == 1
    assert result.evidence[0].raw_evidence["port"] == 80
    assert result.evidence[0].discovery_method == "tcp_connect"


@pytest.mark.asyncio
async def test_port_scanner_default_ports() -> None:
    """Port Scanner should scan default quick profile ports if none are configured."""
    scanner = PortScanner()
    target_info = TargetInfo(original="192.0.2.1", normalized="192.0.2.1", target_type=TARGET_TYPE_IPV4)
    scanner_input = ScannerInput(target=target_info)

    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 12
    assert result.results[0].port == 21
    assert result.results[-1].port == 8443


@pytest.mark.asyncio
async def test_port_scanner_profiles() -> None:
    """Port Scanner should load standard profile ports when configured."""
    scanner = PortScanner()
    target_info = TargetInfo(original="192.0.2.1", normalized="192.0.2.1", target_type=TARGET_TYPE_IPV4)
    scanner_input = ScannerInput(target=target_info, configuration={"profile": "standard", "max_retries": 0})

    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 37  # Standard profile contains 37 ports
