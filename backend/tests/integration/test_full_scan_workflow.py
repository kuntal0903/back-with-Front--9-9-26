"""
tests/integration/test_full_scan_workflow.py

End-to-end integration tests for the complete scan workflow pipeline.
Tests validate the full path from scan creation through orchestration,
cascading sub-asset discovery, asset correlation, and final result aggregation.

All scanners are mocked — no real network calls are made.
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PARTIAL_FAILURE,
    TOOL_DNS_SCAN,
    TOOL_PORT_DISCOVERY,
    TOOL_SERVICE_IDENTIFICATION,
    TOOL_HTTP_SCAN,
    TOOL_TECHNOLOGY_DETECTION,
    TOOL_ENDPOINT_DISCOVERY,
    TOOL_JAVASCRIPT_DISCOVERY,
    TOOL_TLS_SCAN,
    TOOL_EMAIL_SECURITY,
    TOOL_CLOUD_CDN_DETECTION,
)
from app.models.scan import Scan
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerResult

from app.orchestrator.db import scan_db
from app.orchestrator.scan_orchestrator import ScanOrchestrator, SCANNERS

from tests.integration.conftest import (
    mock_all_scanners,
    build_dns_mock,
    build_port_mock,
    build_http_mock,
)


# ─────────────────────────────────────────────
# 1. Domain Full Scan Workflow
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_domain_full_scan_workflow(monkeypatch) -> None:
    """
    Full scan on a domain target exercises the complete pipeline:
      - DNS discovers IPs and MX records
      - Port discovery cascades onto resolved IPs
      - Service identification cascades onto open ports
      - HTTP/TLS run on root target + discovered ports
      - Email security and Cloud/CDN run on domain
      - Technology, Endpoint, JS discovery cascade from HTTP results
      - Assets and relationships are aggregated correctly
    """
    mock_all_scanners(monkeypatch)
    orchestrator = ScanOrchestrator()

    target_info = TargetInfo(
        original="Example.COM",
        normalized="example.com",
        target_type="domain",
    )
    scan = Scan(
        scan_id="integration-domain-full",
        target=target_info,
        status="queued",
        mode="full",
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    # Verify scan completed
    updated_scan = scan_db.get_scan(scan.scan_id)
    assert updated_scan.status in (SCAN_STATUS_COMPLETED, SCAN_STATUS_PARTIAL_FAILURE)
    assert updated_scan.progress == 100

    # Verify results exist
    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    assert result.scan_id == "integration-domain-full"

    # Verify assets were discovered
    assets = result.assets
    asset_types = {a.asset_type for a in assets}

    # Core asset types from DNS → Port → HTTP → TLS pipeline
    assert "domain" in asset_types, "Domain asset should exist"
    assert "ip_address" in asset_types, "IP address from DNS A record should exist"

    # Verify specific discovered values
    ip_assets = [a for a in assets if a.asset_type == "ip_address"]
    assert any(a.normalized_value == "192.0.2.10" for a in ip_assets), \
        "DNS should have resolved 192.0.2.10"

    # Verify relationships exist
    relationships = result.relationships
    assert len(relationships) > 0, "At least one relationship should be discovered"

    # Verify resolves_to relationship exists (domain → IP)
    resolves_to_rels = [r for r in relationships if r.relationship_type == "resolves_to"]
    assert len(resolves_to_rels) > 0, "DNS should create resolves_to relationships"

    # Verify completed timestamps
    assert result.started_at is not None
    assert result.completed_at is not None


# ─────────────────────────────────────────────
# 2. IPv4 Full Scan Workflow
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ipv4_full_scan_workflow(monkeypatch) -> None:
    """
    Full scan on an IPv4 target:
      - Port discovery runs directly on the IP (no DNS needed)
      - Service identification cascades onto open ports
      - HTTP/TLS run on the IP target + ports
      - Cloud/CDN runs on the IP
      - DNS and Email MUST NOT run (incompatible with ipv4)
    """
    mock_all_scanners(monkeypatch)
    orchestrator = ScanOrchestrator()

    target_info = TargetInfo(
        original="192.0.2.50",
        normalized="192.0.2.50",
        target_type="ipv4",
    )
    scan = Scan(
        scan_id="integration-ipv4-full",
        target=target_info,
        status="queued",
        mode="full",
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    updated_scan = scan_db.get_scan(scan.scan_id)
    assert updated_scan.status in (SCAN_STATUS_COMPLETED, SCAN_STATUS_PARTIAL_FAILURE)
    assert updated_scan.progress == 100

    result = scan_db.get_result(scan.scan_id)
    assert result is not None

    # Verify port discovery found open ports on the IP
    assets = result.assets
    port_assets = [a for a in assets if a.asset_type == "network_port"]
    assert len(port_assets) > 0, "Port discovery should find open ports on IP target"

    # Verify at least one port is formatted correctly
    assert any("192.0.2.50:" in a.normalized_value for a in port_assets), \
        "Port assets should be formatted as IP:port"

    # DNS should NOT have been called (no domain assets should appear from DNS)
    # The only IP asset should come from the port scanner's host processing, not DNS
    domain_assets = [a for a in assets if a.asset_type == "domain"]
    assert len(domain_assets) == 0, "DNS should not run on IPv4 targets"


# ─────────────────────────────────────────────
# 3. Individual Scan Workflow
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_individual_scan_workflow(monkeypatch) -> None:
    """
    Individual mode with a single tool (dns_scan).
    Only the selected tool runs, no cascading to other tools.
    """
    mock_all_scanners(monkeypatch)
    orchestrator = ScanOrchestrator()

    target_info = TargetInfo(
        original="example.com",
        normalized="example.com",
        target_type="domain",
    )
    scan = Scan(
        scan_id="integration-individual",
        target=target_info,
        status="queued",
        mode="individual",
        scans=[TOOL_DNS_SCAN],
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    updated_scan = scan_db.get_scan(scan.scan_id)
    assert updated_scan.status == SCAN_STATUS_COMPLETED
    assert updated_scan.progress == 100

    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    assert len(result.errors) == 0

    # DNS should produce domain + IP + MX assets
    assets = result.assets
    assert any(a.asset_type == "domain" for a in assets)
    assert any(a.asset_type == "ip_address" for a in assets)

    # Port scanner should NOT have run (not selected)
    port_assets = [a for a in assets if a.asset_type == "network_port"]
    assert len(port_assets) == 0, "Port scanner should not run in individual dns_scan mode"


# ─────────────────────────────────────────────
# 4. Selected Scan Workflow
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_selected_scan_workflow(monkeypatch) -> None:
    """
    Selected mode with [dns_scan, http_scan].
    Only these two tools run. Port discovery does NOT run.
    """
    mock_all_scanners(monkeypatch)
    orchestrator = ScanOrchestrator()

    target_info = TargetInfo(
        original="example.com",
        normalized="example.com",
        target_type="domain",
    )
    scan = Scan(
        scan_id="integration-selected",
        target=target_info,
        status="queued",
        mode="selected",
        scans=[TOOL_DNS_SCAN, TOOL_HTTP_SCAN],
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    updated_scan = scan_db.get_scan(scan.scan_id)
    assert updated_scan.status == SCAN_STATUS_COMPLETED
    assert updated_scan.progress == 100

    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    assert len(result.errors) == 0

    assets = result.assets

    # DNS ran → domain + IP assets
    assert any(a.asset_type == "domain" for a in assets)
    assert any(a.asset_type == "ip_address" for a in assets)

    # HTTP ran → URL asset
    assert any(a.asset_type == "url" for a in assets)

    # Port discovery did NOT run
    port_assets = [a for a in assets if a.asset_type == "network_port"]
    assert len(port_assets) == 0, "Port discovery should not run when not selected"


# ─────────────────────────────────────────────
# 5. Results Aggregation Correctness
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_results_aggregation_correctness(monkeypatch) -> None:
    """
    Validates that the aggregated ScanResult:
      - Deduplicates assets (domain asset appears once despite multiple scanners)
      - Chains relationships correctly (domain → IP → port)
      - Has all expected structural fields
    """
    mock_all_scanners(monkeypatch)
    orchestrator = ScanOrchestrator()

    target_info = TargetInfo(
        original="example.com",
        normalized="example.com",
        target_type="domain",
    )
    scan = Scan(
        scan_id="integration-aggregation",
        target=target_info,
        status="queued",
        mode="selected",
        scans=[TOOL_DNS_SCAN, TOOL_PORT_DISCOVERY, TOOL_HTTP_SCAN],
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    result = scan_db.get_result(scan.scan_id)
    assert result is not None

    # Verify structural fields
    assert result.scan_id == "integration-aggregation"
    assert result.target.normalized == "example.com"
    assert isinstance(result.assets, list)
    assert isinstance(result.relationships, list)
    assert isinstance(result.errors, list)
    assert isinstance(result.evidence, list)

    # Verify asset deduplication: "example.com" domain should appear exactly once
    domain_assets = [a for a in result.assets if a.asset_type == "domain" and a.normalized_value == "example.com"]
    assert len(domain_assets) == 1, \
        f"Domain asset should be deduplicated to exactly 1, found {len(domain_assets)}"

    # Verify relationship chain: domain resolves_to IP
    rels = result.relationships
    resolves_to = [r for r in rels if r.relationship_type == "resolves_to"]
    assert len(resolves_to) > 0

    # Verify relationship chain: IP exposes port
    exposes = [r for r in rels if r.relationship_type == "exposes"]
    assert len(exposes) > 0, "Port scanner results should create exposes relationships"

    # Verify URL assets from HTTP scanner
    url_assets = [a for a in result.assets if a.asset_type == "url"]
    assert len(url_assets) > 0


# ─────────────────────────────────────────────
# 6. Partial Failure Domain Scan
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_partial_failure_domain_scan(monkeypatch) -> None:
    """
    One scanner succeeds, another crashes.
    The scan status should be partial_failure, successful results are preserved,
    and errors are structured correctly.
    """
    async def crashing_http_execute(self, input_data):
        raise RuntimeError("Simulated HTTP scanner crash")

    mock_all_scanners(monkeypatch, overrides={
        TOOL_HTTP_SCAN: crashing_http_execute,
    })
    orchestrator = ScanOrchestrator()

    target_info = TargetInfo(
        original="example.com",
        normalized="example.com",
        target_type="domain",
    )
    scan = Scan(
        scan_id="integration-partial-failure",
        target=target_info,
        status="queued",
        mode="selected",
        scans=[TOOL_DNS_SCAN, TOOL_HTTP_SCAN],
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    updated_scan = scan_db.get_scan(scan.scan_id)
    assert updated_scan.status == SCAN_STATUS_PARTIAL_FAILURE
    assert updated_scan.progress == 100

    result = scan_db.get_result(scan.scan_id)
    assert result is not None

    # Errors should contain the crash message
    assert len(result.errors) > 0
    error_messages = [e.get("message", "") for e in result.errors]
    assert any("Simulated HTTP scanner crash" in msg for msg in error_messages), \
        f"Crash message not found in errors: {error_messages}"

    # DNS scanner still produced assets despite HTTP failure
    assets = result.assets
    assert any(a.asset_type == "ip_address" for a in assets), \
        "DNS assets should be preserved despite HTTP scanner crash"


# ─────────────────────────────────────────────
# 7. Empty Scan — No Applicable Tools
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_empty_scan_no_applicable_tools(monkeypatch) -> None:
    """
    Selecting tools that are incompatible with the target type.
    The scan should complete with empty results, not crash.
    """
    mock_all_scanners(monkeypatch)
    orchestrator = ScanOrchestrator()

    # email_security is not compatible with IPv4
    target_info = TargetInfo(
        original="192.0.2.99",
        normalized="192.0.2.99",
        target_type="ipv4",
    )
    scan = Scan(
        scan_id="integration-empty",
        target=target_info,
        status="queued",
        mode="selected",
        scans=[TOOL_EMAIL_SECURITY],
    )
    scan_db.save_scan(scan)

    await orchestrator.run_scan(scan.scan_id)

    updated_scan = scan_db.get_scan(scan.scan_id)
    assert updated_scan.status == SCAN_STATUS_COMPLETED
    assert updated_scan.progress == 100

    result = scan_db.get_result(scan.scan_id)
    assert result is not None
    assert len(result.assets) == 0
    assert len(result.relationships) == 0
    assert len(result.errors) == 0


# ─────────────────────────────────────────────
# 8. Full Scan via API Endpoint Integration
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_scan_api_endpoint_integration(monkeypatch) -> None:
    """
    End-to-end via the FastAPI API layer:
      1. POST /api/v1/scans creates the scan and returns 201
      2. Background task runs the orchestrator
      3. GET /api/v1/scans/{id}/results returns 200 with aggregated results
    """
    mock_all_scanners(monkeypatch)

    from app.main import app
    from app.api.routes.scans import orchestrator as route_orchestrator

    # Monkeypatch the route's orchestrator instance to use our mocked scanners
    # The scanners are already monkeypatched at class level via mock_all_scanners

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Create scan
        payload = {
            "target": "example.com",
            "mode": "selected",
            "scans": [TOOL_DNS_SCAN],
        }
        create_response = await client.post("/api/v1/scans", json=payload)

    assert create_response.status_code == 201
    create_data = create_response.json()
    scan_id = create_data["scan_id"]
    assert create_data["status"] == "queued"
    assert create_data["target"]["normalized"] == "example.com"
    assert create_data["target"]["target_type"] == "domain"

    # 2. The background task runs via FastAPI's BackgroundTasks.
    # In test mode with ASGITransport, background tasks execute after the response.
    # We need to manually trigger orchestration since test transport may not run background tasks.
    orchestrator_instance = ScanOrchestrator()
    await orchestrator_instance.run_scan(scan_id)

    # 3. Fetch results
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        results_response = await client.get(f"/api/v1/scans/{scan_id}/results")

    assert results_response.status_code == 200
    results_data = results_response.json()
    assert results_data["scan_id"] == scan_id
    assert isinstance(results_data["assets"], list)
    assert len(results_data["assets"]) > 0, "DNS scan should have produced assets"

    # Verify status endpoint works
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        status_response = await client.get(f"/api/v1/scans/{scan_id}")

    assert status_response.status_code == 200
    status_data = status_response.json()
    assert status_data["progress"] == 100
