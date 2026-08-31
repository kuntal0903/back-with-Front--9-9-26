"""
app/scanners/http/scanner.py

Main HTTP/HTTPS Scanner class subclassing BaseScanner.
Probes target URL directly, or both http and https ports concurrently.
"""

import asyncio

from app.core.config import settings
from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_HTTP_SCAN,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.http.client import probe_http_endpoint
from app.scanners.http.models import HttpRecord


class HttpScanner(BaseScanner):
    """
    HTTP/HTTPS Metadata Scanner tool.
    Collects status codes, Server headers, titles, security headers, cookies, and redirects.
    """

    tool_name = TOOL_HTTP_SCAN

    def validate_input(self, input_data: ScannerInput) -> None:
        """
        Validate that the target is a valid host or URL.
        """
        target_type = input_data.target.target_type
        valid_types = (
            TARGET_TYPE_IPV4,
            TARGET_TYPE_IPV6,
            TARGET_TYPE_DOMAIN,
            TARGET_TYPE_HOSTNAME,
        )
        original = input_data.target.original.lower().strip()
        is_url = original.startswith(("http://", "https://"))

        if target_type not in valid_types and not is_url:
            raise ScannerInputValidationError(
                f"HTTP Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Execute concurrent HTTP and HTTPS queries against the target.
        """
        target = input_data.target.normalized
        config = input_data.configuration

        timeout = float(config.get("timeout", 5.0))
        max_redirects = int(config.get("max_redirects", 5))

        original_lower = input_data.target.original.strip().lower()
        if original_lower.startswith(("http://", "https://")):
            endpoints = [input_data.target.original.strip()]
        else:
            endpoints = [f"http://{target}", f"https://{target}"]

        async def _probe(url: str) -> None:
            scheme = "https" if url.lower().startswith("https://") else "http"
            port = 443 if scheme == "https" else 80
            
            try:
                details = await probe_http_endpoint(
                    url,
                    timeout=timeout,
                    max_redirects=max_redirects,
                )
                
                record = HttpRecord(
                    port=port,
                    scheme=scheme,
                    details=details,
                )
                result.results.append(record)

                # Store supporting evidence
                result.evidence.append(
                    Evidence(
                        source_tool=self.tool_name,
                        discovery_method="http_request",
                        raw_evidence={
                            "url": url,
                            "final_url": details.url,
                            "status_code": details.status_code,
                            "transport_status": details.transport_status,
                            "http_version": details.http_version,
                            "server_product": details.server_product,
                            "server_version": details.server_version,
                            "title": details.title,
                            "content_type": details.content_type,
                            "headers": details.headers,
                            "security_headers": details.security_headers,
                            "cookies": details.cookies,
                            "redirect_chain_len": len(details.redirect_chain),
                            "ssl_verified": details.ssl_verified,
                        },
                        confidence=CONFIDENCE_HIGH,
                    )
                )
            except Exception as e:
                self.logger.warning(
                    "HTTP endpoint probe failed",
                    extra={
                        "url": url,
                        "error": str(e),
                    },
                )

        # Launch HTTP and HTTPS probes concurrently
        tasks = [_probe(url) for url in endpoints]
        await asyncio.gather(*tasks)

        # Sort results deterministically by port (HTTP then HTTPS)
        result.results.sort(key=lambda x: x.port)
        result.evidence.sort(key=lambda x: x.raw_evidence["url"])
