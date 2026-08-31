"""
app/scanners/tech/scanner.py

Main Technology Detection Scanner class subclassing BaseScanner.
Probes target URL directly, or both http and https ports concurrently.
Uses multi-signal evidence extraction and deterministic confidence rules.
"""

import asyncio
import ssl
import httpx

from app.core.config import settings
from app.core.constants import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_TECHNOLOGY_DETECTION,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.tech.fingerprinter import fingerprint_response
from app.scanners.tech.models import TechRecord


class TechScanner(BaseScanner):
    """
    Technology Detection Scanner tool.
    Fingerprints web headers, cookies, scripts, stylesheets, meta tags, and HTML DOM structures.
    """

    tool_name = TOOL_TECHNOLOGY_DETECTION

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
                f"Technology Detection Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Execute concurrent HTTP probes and fingerprint the responses.
        """
        target = input_data.target.normalized
        config = input_data.configuration

        # Read configuration parameters
        timeout = float(config.get("timeout", 5.0))

        # Check if the original target is already a full URL
        original_lower = input_data.target.original.strip().lower()
        if original_lower.startswith(("http://", "https://")):
            endpoints = [input_data.target.original.strip()]
        else:
            endpoints = [f"http://{target}", f"https://{target}"]

        async def _probe(url: str) -> None:
            scheme = "https" if url.lower().startswith("https://") else "http"
            port = 443 if scheme == "https" else 80

            try:
                # Grab headers, body, cookies
                headers, body, cookies = await self._grab_http_response(url, timeout)

                # Perform fingerprint checks
                detected = fingerprint_response(headers, body, cookies)

                if detected:
                    record = TechRecord(
                        port=port,
                        url=url,
                        technologies=detected,
                    )
                    result.results.append(record)

                    # Store supporting evidence for each detected technology
                    for tech in detected:
                        conf_level = (
                            CONFIDENCE_HIGH
                            if tech.confidence == "high"
                            else (CONFIDENCE_MEDIUM if tech.confidence == "medium" else CONFIDENCE_LOW)
                        )
                        result.evidence.append(
                            Evidence(
                                source_tool=self.tool_name,
                                discovery_method="response_fingerprint",
                                raw_evidence={
                                    "url": url,
                                    "technology": tech.name,
                                    "category": tech.category,
                                    "version": tech.version,
                                    "status": tech.status,
                                    "confidence": tech.confidence,
                                    "detection_methods": tech.detection_methods,
                                    "matched_indicators": tech.matched_indicators,
                                    "evidence": [e.model_dump() for e in tech.evidence],
                                },
                                confidence=conf_level,
                            )
                        )
            except Exception as e:
                self.logger.warning(
                    "Technology probe failed",
                    extra={
                        "url": url,
                        "error": str(e),
                    },
                )

        # Launch HTTP and HTTPS probes concurrently
        tasks = [_probe(url) for url in endpoints]
        await asyncio.gather(*tasks)

        # Sort results deterministically by port
        result.results.sort(key=lambda x: x.port)
        result.evidence.sort(key=lambda x: x.raw_evidence["url"])

    async def _grab_http_response(
        self,
        url: str,
        timeout: float,
    ) -> tuple[dict[str, str], str, list[str]]:
        """
        Execute request to retrieve headers, body text, and cookies.
        Uses SSL verification fallback similar to HTTP scanner client.
        """
        try:
            return await self._execute_request(url, timeout, verify_ssl=True)
        except httpx.RequestError as e:
            # Fallback to verify=False if SSL verification failed
            err_str = str(e).lower()
            underlying = e.__cause__
            is_ssl_err = "ssl" in err_str or "cert" in err_str
            if underlying:
                underlying_str = str(underlying).lower()
                if "ssl" in underlying_str or "cert" in underlying_str or isinstance(underlying, ssl.SSLError):
                    is_ssl_err = True

            if is_ssl_err:
                return await self._execute_request(url, timeout, verify_ssl=False)
            raise e

    async def _execute_request(
        self,
        url: str,
        timeout: float,
        verify_ssl: bool,
    ) -> tuple[dict[str, str], str, list[str]]:
        """Conduct request returning HTTP elements."""
        limits = httpx.Limits(max_keepalive_connections=1, max_connections=2)
        async with httpx.AsyncClient(
            verify=verify_ssl,
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            response = await client.get(url)

        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text
        cookies = list(response.cookies.keys())

        return headers, body, cookies
