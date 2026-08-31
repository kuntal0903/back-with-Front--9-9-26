"""
tests/test_scan_orchestrator.py

Unit and integration tests for the Scan Orchestrator: compatibility selection, stage resolution,
duplicate scan prevention, tool execution isolation, and cascading sub-asset queue mapping.
"""

import asyncio
from datetime import datetime, timezone
import pytest

from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PARTIAL_FAILURE,
    SCAN_STATUS_RUNNING,
    TOOL_DNS_SCAN,
    TOOL_PORT_DISCOVERY,
    TOOL_SERVICE_IDENTIFICATION,
    TOOL_HTTP_SCAN,
)
from app.models.scan import Scan
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerResult
from app.scanners.dns.models import DnsRecord
from app.scanners.port.models import PortDiscoveryRecord

from app.services.assets.db import asset_db
from app.orchestrator.db import scan_db
from app.orchestrator.scan_orchestrator import ScanOrchestrator, SCANNERS
from app.orchestrator.dependency_manager import ScanDependencyManager


@pytest.fixture(autouse=True)
def clean_databases() -> None:
    """Fixture ensuring all memory mock databases are cleared before and after each test."""
    asset_db.clear()
    scan_db.clear()
    yield
    asset_db.clear()
    scan_db.clear()


# ─────────────────────────────────────────────
# Unit Tests for Dependency Mappings
# ─────────────────────────────────────────────

def test_dependency_manager_tool_compatibility() -> None:
    """DependencyManager must return correct tools list matching target type classes."""
    manager = ScanDependencyManager()
    
    domain_tools = manager.get_compatible_tools("domain")
    assert TOOL_DNS_SCAN in domain_tools
    assert TOOL_PORT_DISCOVERY not in domain_tools

    ip_tools = manager.get_compatible_tools("ipv4")
    assert TOOL_PORT_DISCOVERY in ip_tools
    assert TOOL_DNS_SCAN not in ip_tools


def test_dependency_manager_execution_order() -> None:
    """DependencyManager must resolve stage lists ensuring dependencies execute in prior stages."""
    manager = ScanDependencyManager()
    
    selected = [TOOL_DNS_SCAN, TOOL_SERVICE_IDENTIFICATION, TOOL_PORT_DISCOVERY]
    stages = manager.resolve_execution_order(selected)
    
    # Expected execution: DNS & Port in Stage 0, Service in Stage 1
    assert len(stages) == 2
    assert TOOL_PORT_DISCOVERY in stages[0]
    assert TOOL_SERVICE_IDENTIFICATION in stages[1]


# ─────────────────────────────────────────────
# Scan Execution and Error Isolation Checks
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_orchestrator_execution_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Orchestrator must isolate failing scanners, continuing the scan and mapping errors."""
    orchestrator = ScanOrchestrator()
    
    # 1. Setup mock scanner execute behaviors
    async def mock_execute_success(self, input_data):
        return ScannerResult(
            tool=TOOL_DNS_SCAN,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[DnsRecord(record_type="A", value="192.0.2.22", ttl=60)],
        )

    async def mock_execute_fail(self, input_data):
        raise RuntimeError("Mock network failure")

    monkeypatch.setattr(SCANNERS[TOOL_DNS_SCAN], "execute", mock_execute_success)
    # We will simulate HTTP scanner crashing
    monkeypatch.setattr(SCANNERS[TOOL_HTTP_SCAN], "execute", mock_execute_fail)

    # 2. Queue scan
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(
        scan_id="scan-test-isolation",
        target=target_info,
        status="queued",
        mode="selected",
        scans=[TOOL_DNS_SCAN, TOOL_HTTP_SCAN],
    )
    scan_db.save_scan(scan)

    # 3. Run scan
    await orchestrator.run_scan(scan.scan_id)

    # Verification
    updated_scan = scan_db.get_scan(scan.scan_id)
    assert updated_scan.status == SCAN_STATUS_PARTIAL_FAILURE
    assert updated_scan.progress == 100

    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    assert len(result.errors) == 1
    assert "Mock network failure" in result.errors[0]["message"]
    
    # Assets must still contain the resolved IP address from successful DNS Scan
    assets = result.assets
    assert len(assets) > 0
    assert any(a.normalized_value == "192.0.2.22" for a in assets)


# ─────────────────────────────────────────────
# Dynamic Cascading Queue Mapping
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_orchestrator_cascading_sub_assets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Orchestrator must dynamically map discovered sub-assets and execute dependent tools on them."""
    orchestrator = ScanOrchestrator()

    # 1. Setup DNS scanner returning IP address, and Port scanner returning open port
    async def mock_dns_execute(self, input_data):
        return ScannerResult(
            tool=TOOL_DNS_SCAN,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[DnsRecord(record_type="A", value="192.0.2.100", ttl=60)],
        )

    async def mock_port_execute(self, input_data):
        return ScannerResult(
            tool=TOOL_PORT_DISCOVERY,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[PortDiscoveryRecord(port=80, protocol="tcp", state="open", reason="accepted", duration_seconds=0.1)],
        )

    monkeypatch.setattr(SCANNERS[TOOL_DNS_SCAN], "execute", mock_dns_execute)
    monkeypatch.setattr(SCANNERS[TOOL_PORT_DISCOVERY], "execute", mock_port_execute)

    # 2. Queue full scan on domain
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(
        scan_id="scan-test-cascade",
        target=target_info,
        status="queued",
        mode="selected",
        scans=[TOOL_DNS_SCAN, TOOL_PORT_DISCOVERY],
    )
    scan_db.save_scan(scan)

    # 3. Run scan
    await orchestrator.run_scan(scan.scan_id)

    # Verification
    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    
    # DNS Scanner executes in Stage 0 -> resolves IP 192.0.2.100
    # Port Discovery executes in Stage 1 -> runs on IP 192.0.2.100 and exposes port 80
    assets = result.assets
    assert any(a.asset_type == "ip_address" and a.normalized_value == "192.0.2.100" for a in assets)
    assert any(a.asset_type == "network_port" and a.normalized_value == "192.0.2.100:80" for a in assets)
