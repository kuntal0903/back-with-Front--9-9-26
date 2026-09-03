"""
app/orchestrator/scan_orchestrator.py

Scan Orchestrator coordinating all completed scanning modules and asset mappings.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PARTIAL_FAILURE,
    SCAN_STATUS_RUNNING,
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
from app.core.exceptions import AttackSurfaceEngineError
from app.models.scan import Scan
from app.models.results import ScanResult
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.dns.scanner import DnsScanner
from app.scanners.port.scanner import PortScanner
from app.scanners.service.scanner import ServiceScanner
from app.scanners.http.scanner import HttpScanner
from app.scanners.tech.scanner import TechScanner
from app.scanners.endpoint.scanner import EndpointScanner
from app.scanners.js.scanner import JsScanner
from app.scanners.tls.scanner import TlsScanner
from app.scanners.email.scanner import EmailScanner
from app.scanners.cloud.scanner import CloudScanner

from app.services.assets.db import asset_db
from app.services.assets.manager import AssetManager
from app.services.target.processor import TargetProcessor
from app.services.target.classifier import classify_target

from app.orchestrator.db import scan_db
from app.orchestrator.dependency_manager import ScanDependencyManager

# Scanner registry
SCANNERS = {
    TOOL_DNS_SCAN: DnsScanner,
    TOOL_PORT_DISCOVERY: PortScanner,
    TOOL_SERVICE_IDENTIFICATION: ServiceScanner,
    TOOL_HTTP_SCAN: HttpScanner,
    TOOL_TECHNOLOGY_DETECTION: TechScanner,
    TOOL_ENDPOINT_DISCOVERY: EndpointScanner,
    TOOL_JAVASCRIPT_DISCOVERY: JsScanner,
    TOOL_TLS_SCAN: TlsScanner,
    TOOL_EMAIL_SECURITY: EmailScanner,
    TOOL_CLOUD_CDN_DETECTION: CloudScanner,
}


class ScanOrchestrator:
    """
    Coordinates scan execution, stage dependency resolution, asset queues, and final aggregation.
    """

    def __init__(self) -> None:
        self.dep_manager = ScanDependencyManager()
        self.asset_manager = AssetManager()
        self.target_processor = TargetProcessor()
        # Limit concurrent scanner execution to prevent system resource exhaustion
        self._semaphore = asyncio.Semaphore(10)

    async def run_scan(self, scan_id: str) -> None:
        """
        Background worker running the scan orchestration pipeline.
        """
        scan = scan_db.get_scan(scan_id)
        if not scan:
            return

        # Clear the global asset store to prevent cross-scan data contamination
        asset_db.clear()

        scan.status = SCAN_STATUS_RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 10
        scan_db.save_scan(scan)

        errors: list[dict[str, Any]] = []
        evidence: list[Any] = []
        completed_runs: set[tuple[str, str]] = set()

        try:
            # 1. Determine compatible tools
            target_type = scan.target.target_type
            if scan.mode == "full":
                selected_tools = self.dep_manager.get_compatible_tools(target_type)
                scan.scans = selected_tools
            else:
                # Filter selected tools by compatibility
                selected_tools = [t for t in scan.scans if self.dep_manager.is_compatible(t, target_type)]

            if not selected_tools:
                scan.status = SCAN_STATUS_COMPLETED
                scan.progress = 100
                scan.completed_at = datetime.now(timezone.utc)
                scan_db.save_scan(scan)
                
                # Save empty scan result
                result = ScanResult(
                    scan_id=scan_id,
                    target=scan.target,
                    assets=[],
                    relationships=[],
                    evidence=[],
                    errors=[],
                    started_at=scan.started_at,
                    completed_at=scan.completed_at,
                )
                scan_db.save_result(result)
                return

            # Resolve execution order stages
            stages = self.dep_manager.resolve_execution_order(selected_tools)
            scan.progress = 20
            scan_db.save_scan(scan)

            total_stages = len(stages)
            for i, stage in enumerate(stages):
                tasks = []
                for tool in stage:
                    tasks.extend(self._prepare_tool_tasks(tool, scan.target, completed_runs))

                if tasks:
                    # Execute tasks in parallel (bounded by semaphore)
                    stage_results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Process execution outcomes
                    for res in stage_results:
                        if isinstance(res, Exception):
                            errors.append({
                                "error_type": "orchestrator_error",
                                "message": str(res),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })
                        elif res:
                            # Map results and errors
                            for err in res.errors:
                                errors.append(err.model_dump())
                            for ev in res.evidence:
                                evidence.append(ev)
                            
                            # Parse into AssetManager
                            if res.status == SCAN_STATUS_COMPLETED:
                                try:
                                    self.asset_manager.process_scanner_result(res, scan_id=scan_id)
                                except Exception as e:
                                    errors.append({
                                        "error_type": "asset_processing_error",
                                        "message": f"Failed to process scanner findings: {str(e)}",
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                    })

                    # Post-stage cascade: re-check all selected tools for new sub-asset
                    # tasks generated from freshly discovered assets. The completed_runs
                    # set ensures no duplicate work. This handles cases where tools in the
                    # same stage discover assets that other tools in the same stage need.
                    cascade_tasks = []
                    for tool in selected_tools:
                        cascade_tasks.extend(self._prepare_tool_tasks(tool, scan.target, completed_runs))

                    if cascade_tasks:
                        cascade_results = await asyncio.gather(*cascade_tasks, return_exceptions=True)
                        for res in cascade_results:
                            if isinstance(res, Exception):
                                errors.append({
                                    "error_type": "orchestrator_error",
                                    "message": str(res),
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                })
                            elif res:
                                for err in res.errors:
                                    errors.append(err.model_dump())
                                for ev in res.evidence:
                                    evidence.append(ev)
                                if res.status == SCAN_STATUS_COMPLETED:
                                    try:
                                        self.asset_manager.process_scanner_result(res, scan_id=scan_id)
                                    except Exception as e:
                                        errors.append({
                                            "error_type": "asset_processing_error",
                                            "message": f"Failed to process scanner findings: {str(e)}",
                                            "timestamp": datetime.now(timezone.utc).isoformat(),
                                        })

                # Progress updates
                scan.progress = min(90, 20 + int((i + 1) / total_stages * 60))
                scan_db.save_scan(scan)

            # 2. Gather assets and relationships
            scan.progress = 95
            scan_db.save_scan(scan)

            assets = asset_db.get_assets_by_scan_id(scan_id)
            relationships = asset_db.get_relationships_by_scan_id(scan_id)

            # Save aggregated result
            scan.completed_at = datetime.now(timezone.utc)
            scan_status = SCAN_STATUS_COMPLETED
            if errors:
                scan_status = SCAN_STATUS_PARTIAL_FAILURE

            scan.status = scan_status
            scan.progress = 100
            scan_db.save_scan(scan)

            final_result = ScanResult(
                scan_id=scan_id,
                target=scan.target,
                assets=assets,
                relationships=relationships,
                evidence=evidence,
                errors=errors,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
            )
            scan_db.save_result(final_result)

        except Exception as e:
            # Overall scan failure
            scan.status = SCAN_STATUS_FAILED
            scan.progress = 100
            scan.completed_at = datetime.now(timezone.utc)
            scan.message = f"Orchestrator encountered critical failure: {str(e)}"
            scan_db.save_scan(scan)

            final_result = ScanResult(
                scan_id=scan_id,
                target=scan.target,
                assets=[],
                relationships=[],
                evidence=evidence,
                errors=errors + [{
                    "error_type": "orchestrator_critical_failure",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }],
                started_at=scan.started_at or datetime.now(timezone.utc),
                completed_at=scan.completed_at,
            )
            scan_db.save_result(final_result)

    def _prepare_tool_tasks(self, tool_name: str, target: TargetInfo, completed_runs: set[tuple[str, str]]) -> list[Any]:
        """
        Prepare lists of coroutines to execute for a specific scanner.
        Can run on the root target or on dynamically discovered sub-assets.
        """
        tasks = []
        scanner_cls = SCANNERS.get(tool_name)
        if not scanner_cls:
            return []

        # Maximum asset queue threshold to prevent infinite discovery loops
        if len(asset_db.get_assets()) > 100:
            return []

        # 1. Base scanners running on root target
        if tool_name in (TOOL_DNS_SCAN, TOOL_CLOUD_CDN_DETECTION):
            run_key = (tool_name, target.normalized)
            if run_key not in completed_runs:
                completed_runs.add(run_key)
                tasks.append(self._run_tool_safely(scanner_cls(), target))

        # 1b. Email Security scanner (Domain-oriented: runs directly on Domain/Hostname, or derived domains for IP targets)
        elif tool_name == TOOL_EMAIL_SECURITY:
            if target.target_type in ("domain", "hostname"):
                run_key = (tool_name, target.normalized)
                if run_key not in completed_runs:
                    completed_runs.add(run_key)
                    tasks.append(self._run_tool_safely(scanner_cls(), target))
            else:
                # Target is IP: only run Email scanner if a legitimate domain context was derived (e.g. PTR or TLS SAN)
                derived_domain_assets = [
                    a for a in asset_db.get_assets() if a.asset_type in ("domain", "hostname")
                    and a.scan_id is not None
                ]
                for asset in derived_domain_assets:
                    run_key = (tool_name, asset.normalized_value)
                    if run_key not in completed_runs:
                        try:
                            domain_info = self.target_processor.process(asset.normalized_value)
                            completed_runs.add(run_key)
                            tasks.append(self._run_tool_safely(scanner_cls(), domain_info))
                        except AttackSurfaceEngineError:
                            pass

        # 2. Port Discovery running on root target or resolved A/AAAA IP assets
        elif tool_name == TOOL_PORT_DISCOVERY:
            run_key = (tool_name, target.normalized)
            if run_key not in completed_runs:
                completed_runs.add(run_key)
                tasks.append(self._run_tool_safely(scanner_cls(), target))

            # Cascading run on resolved IP assets from asset_db
            for asset in asset_db.get_assets():
                if asset.asset_type == "ip_address" and asset.scan_id is not None:
                    run_key = (tool_name, asset.normalized_value)
                    if run_key not in completed_runs:
                        try:
                            ip_info = self.target_processor.process(asset.normalized_value)
                            completed_runs.add(run_key)
                            tasks.append(self._run_tool_safely(scanner_cls(), ip_info))
                        except AttackSurfaceEngineError:
                            pass

        # 3. Service Identification running on open network port sub-assets or root target fallback
        elif tool_name == TOOL_SERVICE_IDENTIFICATION:
            port_assets = [a for a in asset_db.get_assets() if a.asset_type == "network_port" and a.scan_id is not None]
            if port_assets:
                for asset in port_assets:
                    val = asset.normalized_value
                    if ":" in val:
                        host, port_str = val.rsplit(":", 1)
                        try:
                            port = int(port_str)
                            run_key = (tool_name, val)
                            if run_key not in completed_runs:
                                completed_runs.add(run_key)
                                port_info = TargetInfo(original=host, normalized=host, target_type=classify_target(host))
                                tasks.append(self._run_tool_safely(scanner_cls(), port_info, {"ports": [port]}))
                        except Exception:
                            pass
            else:
                run_key = (tool_name, target.normalized)
                if run_key not in completed_runs:
                    completed_runs.add(run_key)
                    tasks.append(self._run_tool_safely(scanner_cls(), target))

        # 4. HTTP/HTTPS and TLS Scanner running on root or resolved ports
        elif tool_name in (TOOL_HTTP_SCAN, TOOL_TLS_SCAN):
            # Run on root target first
            run_key = (tool_name, target.normalized)
            if run_key not in completed_runs:
                completed_runs.add(run_key)
                tasks.append(self._run_tool_safely(scanner_cls(), target))
            
            # Cascading run on discovered network_port sub-assets
            for asset in asset_db.get_assets():
                if asset.asset_type == "network_port" and asset.scan_id is not None:
                    val = asset.normalized_value
                    if ":" in val:
                        host, port_str = val.rsplit(":", 1)
                        try:
                            port = int(port_str)
                            # Only execute HTTP scan on HTTP ports, and TLS scan on TLS ports if service was identified,
                            # or run universally if port matches common schemes
                            is_tls_port = (port in (443, 8443)) or (tool_name == TOOL_TLS_SCAN and port == 443)
                            is_http_port = (port in (80, 8080, 443, 8443)) or (tool_name == TOOL_HTTP_SCAN)
                            
                            should_run = is_tls_port if tool_name == TOOL_TLS_SCAN else is_http_port
                            if should_run:
                                run_key = (tool_name, val)
                                if run_key not in completed_runs:
                                    completed_runs.add(run_key)
                                    port_info = TargetInfo(original=host, normalized=host, target_type=classify_target(host))
                                    tasks.append(self._run_tool_safely(scanner_cls(), port_info, {"port": port}))
                        except Exception:
                            pass

        # 5. Technology, Endpoint, and JS Discovery running on discovered URL assets
        elif tool_name in (TOOL_TECHNOLOGY_DETECTION, TOOL_ENDPOINT_DISCOVERY, TOOL_JAVASCRIPT_DISCOVERY):
            # Probe root URL if http_scan has run on target root
            for asset in asset_db.get_assets():
                if asset.asset_type == "url" and asset.scan_id is not None:
                    val = asset.normalized_value
                    run_key = (tool_name, val)
                    if run_key not in completed_runs:
                        completed_runs.add(run_key)
                        url_info = TargetInfo(original=val, normalized=val, target_type="hostname")
                        tasks.append(self._run_tool_safely(scanner_cls(), url_info))

        return tasks

    async def _run_tool_safely(self, scanner: Any, target: TargetInfo, config: dict[str, Any] = None) -> ScannerResult | None:
        """
        Executes a single scanner within a task semaphore boundary, preventing crashes.
        """
        async with self._semaphore:
            scanner_input = ScannerInput(target=target, configuration=config or {})
            try:
                return await scanner.execute(scanner_input)
            except Exception as e:
                # Standardize partial tool execution crash
                from app.scanners.base.models import ScannerErrorDetail
                return ScannerResult(
                    tool=scanner.tool_name,
                    status=SCAN_STATUS_FAILED,
                    target=target,
                    results=[],
                    errors=[ScannerErrorDetail(error_type="tool_execution_crash", message=str(e))],
                    evidence=[],
                )
