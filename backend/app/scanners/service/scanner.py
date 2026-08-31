"""
app/scanners/service/scanner.py

Main Service Identification Scanner class subclassing BaseScanner.
Grabs banners and matches protocol signatures concurrently on target TCP ports.
"""

import asyncio

from app.core.config import settings
from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_SERVICE_IDENTIFICATION,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.port.validator import validate_ports
from app.scanners.service.client import grab_port_banner
from app.scanners.service.models import ServiceRecord
from app.scanners.service.validator import match_service_signature

DEFAULT_SERVICE_PORTS = [21, 22, 25, 80, 443, 8080, 8443]


class ServiceScanner(BaseScanner):
    """
    Service Identification Scanner tool.
    Grabs network banners and determines running protocol, software name, and versions.
    """

    tool_name = TOOL_SERVICE_IDENTIFICATION

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
                f"Service Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Execute concurrent service banner grabs, bounded by a semaphore.
        """
        host = input_data.target.normalized
        config = input_data.configuration

        # Get list of ports to scan
        config_ports = config.get("ports")
        if config_ports is not None:
            ports_to_scan = validate_ports(config_ports)
        else:
            ports_to_scan = DEFAULT_SERVICE_PORTS

        timeout = float(config.get("timeout", 3.0))
        max_concurrency = int(
            config.get("max_concurrency", settings.default_max_concurrent_scans)
        )

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _bound_grab(port: int) -> None:
            async with semaphore:
                raw_banner, is_tls, alpn = await grab_port_banner(
                    host,
                    port,
                    timeout=timeout,
                )
                
                # If no banner retrieved and no TLS handshake succeeded, return
                if not raw_banner and not is_tls:
                    return

                # Match banner signature via protocol handlers
                sig = match_service_signature(port, raw_banner, is_tls=is_tls)
                
                record = ServiceRecord(
                    port=port,
                    protocol=sig["protocol"],
                    software_name=sig["software_name"],
                    software_version=sig["software_version"],
                    is_tls=sig.get("is_tls", is_tls),
                    alpn=alpn,
                    confidence=sig.get("confidence", "high"),
                    raw_banner=raw_banner if raw_banner else None,
                    extra_attributes=sig.get("extra", {}),
                )
                result.results.append(record)

                # Store supporting evidence
                result.evidence.append(
                    Evidence(
                        source_tool=self.tool_name,
                        discovery_method="banner_grab",
                        raw_evidence={
                            "port": port,
                            "protocol": sig["protocol"],
                            "software_name": sig["software_name"],
                            "software_version": sig["software_version"],
                            "is_tls": sig.get("is_tls", is_tls),
                            "alpn": alpn,
                            "raw_banner": raw_banner,
                            "extra": sig.get("extra", {}),
                        },
                        confidence=sig.get("confidence", CONFIDENCE_HIGH),
                    )
                )

        # Launch all grabs concurrently
        tasks = [_bound_grab(port) for port in ports_to_scan]
        await asyncio.gather(*tasks)

        # Sort results by port number for deterministic outputs
        result.results.sort(key=lambda x: x.port)
        result.evidence.sort(key=lambda x: x.raw_evidence["port"])

        self.logger.debug(
            "Service identification scan completed",
            extra={
                "target": host,
                "ports_scanned": len(ports_to_scan),
                "services_identified": len(result.results),
            },
        )
