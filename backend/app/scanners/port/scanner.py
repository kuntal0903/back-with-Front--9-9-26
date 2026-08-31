"""
app/scanners/port/scanner.py

Main Port Discovery Scanner class subclassing BaseScanner.
Scans configured ports concurrently, managing socket concurrency limits.
Supports port profiles (quick, standard, custom), retries, and non-binding service hints.
"""

import asyncio

from app.core.config import settings
from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_PORT_DISCOVERY,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.port.connector import probe_tcp_port, probe_udp_port
from app.scanners.port.models import PortDiscoveryRecord
from app.scanners.port.response_analyzer import get_service_hint
from app.scanners.port.validator import validate_ports

# Quick scan profile: top 12 common web / remote access ports
QUICK_PROFILE_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080, 8443]

# Standard scan profile: top web, database, system admin ports
STANDARD_PROFILE_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1025, 1433, 1521, 2082, 2083, 3000, 3306, 3389, 5432, 5900,
    6379, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 27017
]


class PortScanner(BaseScanner):
    """
    Port Discovery Scanner tool.
    Probes TCP and UDP ports asynchronously to determine network reachability.
    """

    tool_name = TOOL_PORT_DISCOVERY

    def validate_input(self, input_data: ScannerInput) -> None:
        """
        Validate that the target is a valid IP or domain hostname.
        """
        target_type = input_data.target.target_type
        valid_types = (
            TARGET_TYPE_IPV4,
            TARGET_TYPE_IPV6,
            TARGET_TYPE_DOMAIN,
            TARGET_TYPE_HOSTNAME,
        )
        if target_type not in valid_types:
            raise ScannerInputValidationError(
                f"Port Discovery Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Execute concurrent port probes, bounded by a semaphore to limit concurrent sockets.
        """
        host = input_data.target.normalized
        config = input_data.configuration

        # Determine ports list based on explicit config or profile
        profile = str(config.get("profile", "quick")).lower()
        config_ports = config.get("ports")

        if config_ports is not None:
            ports_to_scan = validate_ports(config_ports)
        elif profile == "standard":
            ports_to_scan = STANDARD_PROFILE_PORTS
        else:
            ports_to_scan = QUICK_PROFILE_PORTS

        protocol = str(config.get("protocol", "tcp")).lower()
        timeout = float(config.get("timeout", 2.0))
        max_retries = int(config.get("max_retries", 1))
        max_concurrency = int(
            config.get("max_concurrency", settings.default_max_concurrent_scans)
        )

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _bound_probe(port: int) -> None:
            async with semaphore:
                if protocol == "udp":
                    state, reason, duration, attempts = await probe_udp_port(
                        host, port, timeout=timeout
                    )
                    method = "udp_probe"
                else:
                    state, reason, duration, attempts = await probe_tcp_port(
                        host, port, timeout=timeout, max_retries=max_retries
                    )
                    method = "tcp_connect"

                service_hint = get_service_hint(port, protocol=protocol)

                record = PortDiscoveryRecord(
                    port=port,
                    protocol=protocol,
                    state=state,
                    reason=reason,
                    duration_seconds=duration,
                    method=method,
                    attempt_count=attempts,
                    service_hint=service_hint,
                )
                result.results.append(record)

                # Store evidence for open or open_or_filtered ports
                if state in ("open", "open_or_filtered"):
                    result.evidence.append(
                        Evidence(
                            source_tool=self.tool_name,
                            discovery_method=method,
                            raw_evidence={
                                "port": port,
                                "protocol": protocol,
                                "state": state,
                                "reason": reason,
                                "duration_seconds": duration,
                                "method": method,
                                "attempt_count": attempts,
                                "service_hint": service_hint,
                            },
                            confidence=CONFIDENCE_HIGH if state == "open" else "medium",
                        )
                    )

        # Launch all port probes concurrently, bounded by the semaphore
        tasks = [_bound_probe(port) for port in ports_to_scan]
        await asyncio.gather(*tasks)

        # Sort results by port number for deterministic output structure
        result.results.sort(key=lambda x: x.port)
        result.evidence.sort(key=lambda x: x.raw_evidence["port"])

        self.logger.debug(
            "Port discovery scan finished",
            extra={
                "target": host,
                "total_ports_scanned": len(ports_to_scan),
                "open_ports_found": len(result.evidence),
            },
        )
