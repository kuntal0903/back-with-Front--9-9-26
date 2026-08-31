"""
tests/test_scanner_framework.py

Tests verifying the BaseScanner lifecycle and execution wrapper logic.
"""

import pytest

from app.core.constants import TARGET_TYPE_DOMAIN
from app.core.exceptions import AttackSurfaceEngineError, ConnectionError
from app.schemas.scan_request import TargetInfo
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult


# ─────────────────────────────────────────────
# Test Mock Scanners
# ─────────────────────────────────────────────

class MockSuccessScanner(BaseScanner):
    tool_name = "mock_success"

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        result.results.append({"discovered_asset": "example.com"})


class MockValidateFailScanner(BaseScanner):
    tool_name = "mock_validate_fail"

    def validate_input(self, input_data: ScannerInput) -> None:
        raise ScannerInputValidationError("This scanner only supports domain targets.")

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        pass


class MockDomainErrorScanner(BaseScanner):
    tool_name = "mock_domain_error"

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        raise ConnectionError("Host target is unreachable.")


class MockUnexpectedCrashScanner(BaseScanner):
    tool_name = "mock_unexpected_crash"

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        raise RuntimeError("Out of memory error in native library.")


# ─────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────

def test_base_scanner_requires_tool_name() -> None:
    """TypeError should be raised if BaseScanner subclass has no tool_name defined."""
    with pytest.raises(TypeError) as exc_info:
        class NoNameScanner(BaseScanner):  # type: ignore
            async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
                pass
        NoNameScanner()
    assert "must define a non-empty 'tool_name'" in str(exc_info.value)


@pytest.mark.asyncio
async def test_scanner_success_flow() -> None:
    """A successful scanner run must return status 'completed' and populated findings."""
    scanner = MockSuccessScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    result = await scanner.execute(scanner_input)
    assert result.tool == "mock_success"
    assert result.status == "completed"
    assert len(result.errors) == 0
    assert result.results == [{"discovered_asset": "example.com"}]
    assert result.completed_at >= result.started_at


@pytest.mark.asyncio
async def test_scanner_validation_failure() -> None:
    """Input validation error must set status 'failed' and append error details."""
    scanner = MockValidateFailScanner()
    target_info = TargetInfo(original="127.0.0.1", normalized="127.0.0.1", target_type="ipv4")
    scanner_input = ScannerInput(target=target_info)

    result = await scanner.execute(scanner_input)
    assert result.status == "failed"
    assert len(result.errors) == 1
    assert result.errors[0].error_type == "invalid_input"
    assert "only supports domain targets" in result.errors[0].message


@pytest.mark.asyncio
async def test_scanner_domain_error_handling() -> None:
    """Typed domain exception must be caught, mapped, and status set to 'failed'."""
    scanner = MockDomainErrorScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    result = await scanner.execute(scanner_input)
    assert result.status == "failed"
    assert len(result.errors) == 1
    assert result.errors[0].error_type == "connection_error"
    assert "Host target is unreachable" in result.errors[0].message


@pytest.mark.asyncio
async def test_scanner_unexpected_crash_handling() -> None:
    """Any unhandled system exception must be converted to 'internal_error'."""
    scanner = MockUnexpectedCrashScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    result = await scanner.execute(scanner_input)
    assert result.status == "failed"
    assert len(result.errors) == 1
    assert result.errors[0].error_type == "internal_error"
    assert "Out of memory" in result.errors[0].message
