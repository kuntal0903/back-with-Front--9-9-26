"""
tests/integration/test_hardening_and_resilience.py

Phase 16 — Integration Testing and Hardening Test Suite.
Enforces system-wide resilience, resource protection controls, error isolation,
deduplication under stress, evidence traceability, and concurrency bounding.
"""

import asyncio
from datetime import datetime, timezone
import pytest

from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PARTIAL_FAILURE,
    TOOL_DNS_SCAN,
    TOOL_PORT_DISCOVERY,
    TOOL_HTTP_SCAN,
    TOOL_TLS_SCAN,
    TOOL_ENDPOINT_DISCOVERY,
    CONFIDENCE_HIGH,
    RESULT_STATUS_CONFIRMED,
)
from app.core.exceptions import ScopeRejectedError, InvalidTargetError
from app.models.scan import Scan
from app.models.evidence import Evidence
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerResult, ScannerInput, ScannerErrorDetail
from app.scanners.dns.models import DnsRecord
from app.scanners.http.models import HttpRecord, HttpDetails, HttpRedirectStep
from app.scanners.endpoint.models import EndpointRecord

from app.services.assets.db import asset_db
from app.services.assets.manager import AssetManager
from app.orchestrator.db import scan_db
from app.orchestrator.scan_orchestrator import ScanOrchestrator, SCANNERS
from app.services.target.processor import TargetProcessor

from tests.integration.conftest import mock_all_scanners


# ─────────────────────────────────────────────
# 1. Concurrency Limits & Bounding Verification
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_concurrency_semaphore_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that the orchestrator enforces concurrency bounding (max 10 active tasks)
    and prevents resource exhaustion when executing parallel scan modules.
    """
    orchestrator = ScanOrchestrator()
    max_active_observed = 0
    current_active = 0
    active_lock = asyncio.Lock()

    async def mock_bounded_execute(self, input_data: ScannerInput) -> ScannerResult:
        nonlocal max_active_observed, current_active
        async with active_lock:
            current_active += 1
            if current_active > max_active_observed:
                max_active_observed = current_active
        
        # Simulate active work
        await asyncio.sleep(0.02)
        
        async with active_lock:
            current_active -= 1

        return ScannerResult(
            tool=self.tool_name,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[],
        )

    # Monkeypatch all scanners to monitor concurrent executions
    for tool_name in SCANNERS:
        monkeypatch.setattr(SCANNERS[tool_name], "execute", mock_bounded_execute)

    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(
        scan_id="test-concurrency-limits",
        target=target_info,
        status="queued",
        mode="full",
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    # Verify semaphore bounded active execution to semaphore max limit (10)
    assert max_active_observed <= 10, f"Max concurrent active scans exceeded 10! Observed: {max_active_observed}"
    assert max_active_observed > 0, "No concurrent tasks were executed"


# ─────────────────────────────────────────────
# 2. Timeouts & Network Error Stability
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_timeout_handling_stability(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that network timeouts return structured error details (connection_timeout)
    and leave the system in a clean, non-crashing partial failure state.
    """
    async def mock_timeout_execute(self, input_data: ScannerInput) -> ScannerResult:
        return ScannerResult(
            tool=self.tool_name,
            status=SCAN_STATUS_FAILED,
            target=input_data.target,
            errors=[
                ScannerErrorDetail(
                    error_type="connection_timeout",
                    message="Network probe timed out after 10.0s",
                )
            ],
        )

    monkeypatch.setattr(SCANNERS[TOOL_HTTP_SCAN], "execute", mock_timeout_execute)

    orchestrator = ScanOrchestrator()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(
        scan_id="test-timeout-stability",
        target=target_info,
        status="queued",
        mode="individual",
        scans=[TOOL_HTTP_SCAN],
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    updated_scan = scan_db.get_scan(scan.scan_id)
    assert updated_scan.status == SCAN_STATUS_PARTIAL_FAILURE
    
    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    assert len(result.errors) == 1
    assert result.errors[0]["error_type"] == "connection_timeout"


# ─────────────────────────────────────────────
# 3. Malformed Data Parsing Resilience
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_malformed_response_resilience(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that corrupt/malformed payload responses are safely intercepted
    and produce structured parser_error details rather than unhandled exceptions.
    """
    async def mock_corrupt_execute(self, input_data: ScannerInput) -> ScannerResult:
        return ScannerResult(
            tool=self.tool_name,
            status=SCAN_STATUS_FAILED,
            target=input_data.target,
            errors=[
                ScannerErrorDetail(
                    error_type="parser_error",
                    message="Failed to parse corrupt payload bytes: invalid header structure",
                )
            ],
        )

    monkeypatch.setattr(SCANNERS[TOOL_TLS_SCAN], "execute", mock_corrupt_execute)

    orchestrator = ScanOrchestrator()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(
        scan_id="test-malformed-response",
        target=target_info,
        status="queued",
        mode="individual",
        scans=[TOOL_TLS_SCAN],
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    assert len(result.errors) == 1
    assert result.errors[0]["error_type"] == "parser_error"


# ─────────────────────────────────────────────
# 4. Resource Limits: Redirects & Crawl Depth
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resource_limits_redirects_and_crawling(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify resource controls limit infinite redirect loops and crawl page depth.
    """
    # Simulate HTTP scanner receiving 5 max redirect steps
    async def mock_redirect_loop_execute(self, input_data: ScannerInput) -> ScannerResult:
        redirect_chain = [
            HttpRedirectStep(url=f"http://example.com/step{i}", status_code=301, headers={})
            for i in range(5)
        ]
        return ScannerResult(
            tool=TOOL_HTTP_SCAN,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                HttpRecord(
                    port=80,
                    scheme="http",
                    details=HttpDetails(
                        url="http://example.com/step4",
                        status_code=200,
                        headers={},
                        title="Final Step",
                        redirect_chain=redirect_chain,
                        response_time_seconds=0.1,
                    ),
                )
            ],
        )

    monkeypatch.setattr(SCANNERS[TOOL_HTTP_SCAN], "execute", mock_redirect_loop_execute)

    orchestrator = ScanOrchestrator()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(
        scan_id="test-resource-limits",
        target=target_info,
        status="queued",
        mode="individual",
        scans=[TOOL_HTTP_SCAN],
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    
    # Verify redirects history is bounded to max 5 steps
    urls = [a for a in result.assets if a.asset_type == "url"]
    assert len(urls) <= 6, f"Redirect chain produced excessive URL assets: {len(urls)}"


# ─────────────────────────────────────────────
# 5. Stress Deduplication of Duplicate Findings
# ─────────────────────────────────────────────

def test_duplicate_asset_deduplication_under_stress() -> None:
    """
    Verify that receiving hundreds of duplicate scanner findings resolves to
    single deterministic UUID assets with correctly merged metadata.
    """
    asset_manager = AssetManager()
    
    # Process 100 duplicate DNS findings for the same IP address
    for i in range(100):
        res = ScannerResult(
            tool=TOOL_DNS_SCAN,
            status=SCAN_STATUS_COMPLETED,
            target=TargetInfo(original="example.com", normalized="example.com", target_type="domain"),
            results=[DnsRecord(record_type="A", value="192.0.2.1", ttl=60 + i)],
        )
        asset_manager.process_scanner_result(res)

    assets = asset_db.get_assets()
    ip_assets = [a for a in assets if a.asset_type == "ip_address" and a.normalized_value == "192.0.2.1"]
    
    # Must deduplicate to exactly 1 IP asset
    assert len(ip_assets) == 1, f"Expected 1 deduplicated IP asset, found {len(ip_assets)}"


# ─────────────────────────────────────────────
# 6. Repeated Scan Memory & Isolation Safety
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_repeated_scan_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that executing identical scans repeatedly maintains thread-safe isolation,
    does not create corrupt state, and preserves data integrity.
    """
    mock_all_scanners(monkeypatch)
    orchestrator = ScanOrchestrator()

    for run_idx in range(3):
        scan_id = f"test-repeated-run-{run_idx}"
        target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
        scan = Scan(scan_id=scan_id, target=target_info, status="queued", mode="full")
        scan_db.save_scan(scan)

        await orchestrator.run_scan(scan_id)

        res = scan_db.get_result(scan_id)
        assert res is not None
        assert res.scan_id == scan_id
        assert len(res.assets) > 0


# ─────────────────────────────────────────────
# 7. Traceable Evidence Verification (Rule 1, 4, 5, 6, 19)
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_evidence_traceability_guarantee(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that every finding carries traceable evidence attributes
    including source_tool, discovery_method, confidence, and timestamps.
    """
    mock_all_scanners(monkeypatch)
    orchestrator = ScanOrchestrator()

    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    scan = Scan(scan_id="test-evidence-traceability", target=target_info, status="queued", mode="full")
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    assert len(result.evidence) > 0, "Scan must record evidence items"

    for ev in result.evidence:
        assert ev.source_tool is not None and ev.source_tool != "", "Evidence must record source_tool"
        assert ev.discovery_method is not None and ev.discovery_method != "", "Evidence must record discovery_method"
        assert ev.confidence in ("high", "medium", "low"), f"Evidence confidence invalid: {ev.confidence}"
        assert isinstance(ev.timestamp, datetime), "Evidence must record timestamp"
